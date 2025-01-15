package org.qlein.oidcproxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Context;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.httpproxy.HttpProxy;
import java.io.IOException;
import java.net.URL;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Collectors;
import net.minidev.json.JSONObject;

public class MainVerticle extends AbstractVerticle {

  protected static final int SLEEP_DURATION = 1900;
  protected static final String LABEL_BACKEND_ID = "backendId";
  private static final String LABEL_TYPE = "type";
  private static final String CONFIG_MAP_TYPE_OIDC = "backendOidc";
  protected static final Comparator<BackendConfig> BACKEND_CONFIG_COMPARATOR =
      (config1, config2) ->
          -config1.getPathPrefix().compareTo(config2.getPathPrefix());
  private static final Logger LOGGER = LoggerFactory.getLogger(MainVerticle.class);

  public static final String BEARER_PREFIX = "Bearer ";
  public static final String DEFAULT_HEADER_PREFIX = "X-auth-";
  public static final int DEFAULT_PROXY_PORT = 8080;
  public static final String OIDC_PROXY_PORT = "OIDC_PROXY_PORT";

  private int proxyPort;

  private ConfigRetriever myConfigRetriver;
  private HttpClient client;
  private List<BackendConfig> backendConfigs = new Vector<>();

  private KubernetesClient kubernetesClient;
  private HttpServer httpServer;
  private JsonMapper jsonMapper = JsonMapper.builder().build();

  private boolean checkConfigMapLabels(ConfigMap configMap) {
    Map<String, String> labels = configMap.getMetadata().getLabels();
    String backendId = labels.get(LABEL_BACKEND_ID);
    String type = labels.get(LABEL_TYPE);
    LOGGER.trace(
        "Checking config map {}, backend label: {}, type label: {}",
        configMap.getMetadata().getName(),
        backendId,
        type
    );
    return backendId != null && CONFIG_MAP_TYPE_OIDC.equals(type);
  }

  @Override
  public void init(Vertx vertx, Context context) {
    super.init(vertx, context);

    initKubernetesClient();

    ConfigStoreOptions jsonEnvConfig = new ConfigStoreOptions()
        .setType("env")
        .setConfig(
            new JsonObject()
                .put(
                    "keys",
                    new JsonArray()
                        .add(OIDC_PROXY_PORT)
                )
        );
    ConfigRetrieverOptions myOptions = new ConfigRetrieverOptions().addStore(jsonEnvConfig);
    myConfigRetriver = ConfigRetriever.create(vertx, myOptions);

    client = vertx.createHttpClient(
        new HttpClientOptions()
            .setMaxInitialLineLength(10000)
            .setLogActivity(true)
    );
  }

  private void initKubernetesClient() {
    kubernetesClient = new KubernetesClientBuilder().build();
  }

  @Override
  public void start(Promise<Void> startPromise) {

    myConfigRetriver
        .getConfig()
        .onSuccess(
            asyncResults -> {
              if (!loadConfigValues(asyncResults)) {
                startPromise.fail(
                    "Invalid or incomplete config, missing one or more env variables");
                return;
              }
              initProxy(startPromise);
              vertx.setPeriodic(1000L, 10000l, this::loadBackends);
            }
        )
        .onFailure(
            e -> startPromise.fail("Can't load config: " + e.getMessage())
        );
  }

  private void loadBackends(Long aLong) {
    LOGGER.trace("Loading config maps");
    Set<String> foundBackends = kubernetesClient
        .configMaps()
        .list()
        .getItems()
        .stream()
        .filter(this::checkConfigMapLabels)
        .map(this::addConfigMap)
        .collect(Collectors.toSet());

    backendConfigs
        .stream()
        .filter(backendConfig -> !foundBackends.contains(backendConfig.getBackendId()))
        .collect(Collectors.toSet())
        .forEach(this::removeBackend);
  }

  private void removeBackend(BackendConfig backendConfig) {
    LOGGER.info(
        "Removing backend [{}:{}]",
        backendConfig.getBackendId(),
        backendConfig.getPathPrefix()
    );
    backendConfigs.remove(backendConfig);
  }

  private String addConfigMap(ConfigMap configMap) {
    String backendId = configMap.getMetadata().getLabels().get(LABEL_BACKEND_ID);
    for (Entry<String, String> configJsonEntry : configMap.getData().entrySet()) {
      try {
        addOrUpdateBackend(
            jsonMapper
                .readValue(configJsonEntry.getValue(), BackendConfig.class)
                .setBackendId(backendId)
                .setConfigMapField(configJsonEntry.getKey())
        );
      } catch (JsonProcessingException e) {
        LOGGER.error(
            "Parsing of config map [{}] failed, cause: {} - {}",
            configMap.getMetadata().getName(),
            e.getClass().getSimpleName(),
            e.getMessage(),
            e
        );
      }
    }
    return backendId;
  }


  private boolean loadConfigValues(JsonObject asyncResults) {
    LOGGER.info("Loaded config values: {}", asyncResults.encodePrettily());
    proxyPort = asyncResults.getInteger(OIDC_PROXY_PORT, DEFAULT_PROXY_PORT);
    return true;
  }

  private void initProxy(Promise<Void> startPromise) {
    httpServer = vertx
        .createHttpServer()
        .requestHandler(req -> {
          HttpServerResponse response = req.response();

          String authorizationHeaderValue = req.getHeader(HttpHeaders.AUTHORIZATION);

          if (authorizationHeaderValue == null) {
            RequestProcessor.sendUnauthorized(req, response, "Auth header missing");
          } else if (!authorizationHeaderValue.startsWith(BEARER_PREFIX)) {
            RequestProcessor.sendUnauthorized(req, response, "Bearer missing");
          } else {
            final String accessToken = authorizationHeaderValue.substring(BEARER_PREFIX.length());
            if (LOGGER.isTraceEnabled()) {
              LOGGER.trace("Token: {}", accessToken);
            }
            List<BackendConfig> matchingBackends = backendConfigs
                .stream()
                .filter(backendConfig -> matchRequest(req, backendConfig))
                .sorted(BACKEND_CONFIG_COMPARATOR)
                .toList();
            if (matchingBackends.isEmpty()) {
              RequestProcessor.sendUnauthorized(req, response, "Unknown instance");
              return;
            }
            BackendConfig backendConfig = matchingBackends.get(0);
            LOGGER.trace(
                "Backend config with path prefix [{}] will be used to process request",
                backendConfig.getPathPrefix()
            );
            RequestProcessor.processRequestWithBackend(accessToken, req, response, backendConfig);
          }

        })
        .listen(proxyPort, http -> {
              if (http.succeeded()) {
                startPromise.complete();
                LOGGER.info("HTTP server started on port {}", proxyPort);
              } else {
                startPromise.fail(http.cause());
              }
            }
        );
  }

  private boolean matchRequest(HttpServerRequest req, BackendConfig backendConfig) {
    LOGGER.trace(
        "Matching request to host [{}] and path [{}] against config with path prefix [{}]",
        req.getHeader("Host"),
        req.path(),
        backendConfig.getPathPrefix()
    );
    boolean pathMatches = req.path().startsWith(backendConfig.getPathPrefix());

    boolean headersMatch = true;
    if (backendConfig.getHeaderFilter() != null && !backendConfig.getHeaderFilter().isEmpty()) {
      for (Entry<String, String> headerFilterEntry : backendConfig.getHeaderFilter().entrySet()) {
        String headerValue = req.getHeader(headerFilterEntry.getKey());
        if (headerValue == null || !headerValue.equals(headerFilterEntry.getValue())) {
          LOGGER.debug(
              "Request does not match header filter with key [{}], value [{}] and expected value [{}]",
              headerFilterEntry.getKey(),
              headerFilterEntry.getValue(),
              headerValue
          );
          headersMatch = false;
          break;
        }
      }
    }

    return pathMatches && headersMatch;
  }

  public void addOrUpdateBackend(BackendConfig backendConfig) {

    Optional<BackendConfig> optionalExistingConfig = backendConfigs
        .stream()
        .filter(
            existingConfig -> existingConfig.getBackendId().equals(backendConfig.getBackendId()) &&
                existingConfig.getConfigMapField().equals(backendConfig.getConfigMapField()))
        .findFirst();

    boolean initRequired = optionalExistingConfig
        .map(existingConfig -> !backendConfig.sameRealmAndBackend(existingConfig))
        .orElse(true);

    if (initRequired) {
      if (optionalExistingConfig.isEmpty()) {
        LOGGER.info(
            "Adding backend [{}:{}] => {}:{}",
            backendConfig.getBackendId(),
            backendConfig.getPathPrefix(),
            backendConfig.getBackendHost(),
            backendConfig.getBackendPort()
        );
      } else {
        LOGGER.info(
            "Reinitializing backend [{}:{}] => {}:{}",
            backendConfig.getBackendId(),
            backendConfig.getPathPrefix(),
            backendConfig.getBackendHost(),
            backendConfig.getBackendPort()
        );
      }
      try {
        initTokenProcessor(backendConfig);
      } catch (Throwable e) {
        LOGGER.error(
            "Jwt processor init failed, cause: {} - {}",
            e.getClass().getSimpleName(),
            e.getMessage(),
            e
        );
        return;
      }
      initHttpProxy(backendConfig);

      //if jwt processor and reverse proxy was created (because of new config or
      // changed backend or realm values), then we remove existing config if one exists
      optionalExistingConfig.ifPresent(backendConfigs::remove);
      backendConfigs.add(backendConfig);
    } else {
      LOGGER.trace(
          "Updating backend [{}:{}] => {}:{}",
          backendConfig.getBackendId(),
          backendConfig.getPathPrefix(),
          backendConfig.getBackendHost(),
          backendConfig.getBackendPort()
      );

      //if a config already exists and realm and backend values are the same, then just replace filters
      optionalExistingConfig
          .get()
          .setHeaderFilter(backendConfig.getHeaderFilter())
          .setClaimFilter(backendConfig.getClaimFilter());
    }
  }

  private void initHttpProxy(BackendConfig backendConfig) {
    LOGGER.info(
        "Initializing proxy for backend [{}] with path prefix [{}]",
        backendConfig.getBackendId(),
        backendConfig.getPathPrefix()
    );
    backendConfig.setProxy(
        HttpProxy
            .reverseProxy(client)
            .origin(backendConfig.getBackendPort(), backendConfig.getBackendHost())
    );
  }

  public static OIDCProviderMetadata resolve(final BackendConfig backendConfig)
      throws GeneralException, IOException {

    HTTPRequestConfigurator requestConfigurator = httpRequest -> {
      httpRequest.setConnectTimeout(20000);
      httpRequest.setReadTimeout(20000);
    };

    Issuer issuer = new Issuer(
        Optional
            .ofNullable(backendConfig.getRealmInternalUrl())
            .orElse(backendConfig.getRealmUrl())
    );

    URL configURL = OIDCProviderMetadata.resolveURL(issuer);

    HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, configURL);
    requestConfigurator.configure(httpRequest);

    HTTPResponse httpResponse = httpRequest.send();

    if (httpResponse.getStatusCode() != 200) {
      throw new IOException("Couldn't download OpenID Provider metadata from " + configURL +
          ": Status code " + httpResponse.getStatusCode());
    }

    String responseBody = httpResponse.getBody();
//    if (backendConfig.getRealmInternalUrl() != null) {
//      responseBody = responseBody.replaceAll(
//          backendConfig.getRealmUrl(),
//          backendConfig.getRealmInternalUrl()
//      );
//    }
    JSONObject jsonObject = JSONObjectUtils.parse(responseBody);
    if (backendConfig.getRealmInternalUrl() != null) {
      jsonObject.put(
          "jwks_uri",
          ((String) jsonObject.get("jwks_uri"))
              .replaceAll(
                  backendConfig.getRealmUrl(),
                  backendConfig.getRealmInternalUrl()
              )
      );
    }

    return OIDCProviderMetadata.parse(jsonObject);
  }

  public static void initTokenProcessor(BackendConfig config) throws GeneralException, IOException {
    // Will resolve the OpenID provider metadata automatically
    OIDCProviderMetadata opMetadata = resolve(config);

    // Print the metadata
    LOGGER.debug("OIDC provider meta data: {}", opMetadata.toJSONObject());

    DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

    jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));
    JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(opMetadata.getJWKSetURI().toURL());

    JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
        new HashSet<>(opMetadata.getIDTokenJWSAlgs()),
        keySource
    );

    jwtProcessor.setJWSKeySelector(keySelector);

    jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
        new JWTClaimsSet.Builder().build(),
        new HashSet<>(List.of("sub", "typ", "iat"))
    ));

    config.setJwtProcessor(jwtProcessor);
  }

}
