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
import com.nimbusds.oauth2.sdk.id.Issuer;
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
import java.text.ParseException;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Collectors;

public class MainVerticle extends AbstractVerticle {

  protected static final int SLEEP_DURATION = 1900;
  protected static final String LABEL_TENANT_ID = "tenantId";
  private static final String LABEL_TYPE = "type";
  private static final String CONFIG_MAP_TYPE_OIDC = "tenantOidc";
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
    String tenantId = labels.get(LABEL_TENANT_ID);
    String type = labels.get(LABEL_TYPE);
    LOGGER.trace(
        "Checking config map {}, tenant label: {}, type label: {}",
        configMap.getMetadata().getName(),
        tenantId,
        type
    );
    return tenantId != null && CONFIG_MAP_TYPE_OIDC.equals(type);
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
    LOGGER.debug("Loading config maps");
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
    //TODO find out how to destroy jwt processor and http proxy objects
    backendConfigs.remove(backendConfig);
  }

  private String addConfigMap(ConfigMap configMap) {
    String tenantId = configMap.getMetadata().getLabels().get(LABEL_TENANT_ID);
    for (Entry<String, String> configJsonEntry : configMap.getData().entrySet()) {
      try {
        addOrUpdateBackend(
            jsonMapper
                .readValue(configJsonEntry.getValue(), BackendConfig.class)
                .setBackendId(tenantId)
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
    return tenantId;
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
            sendUnauthorized(response, "Auth header missing");
          } else if (!authorizationHeaderValue.startsWith(BEARER_PREFIX)) {
            sendUnauthorized(response, "Bearer missing");
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
              sendUnauthorized(response, "Unknown instance");
              return;
            }
            BackendConfig backendConfig = matchingBackends.get(0);
            LOGGER.trace(
                "Backend config with path prefix [{}] will be used to process request",
                backendConfig.getPathPrefix()
            );
            processRequestWithBackend(accessToken, req, response, backendConfig);
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

  private void processRequestWithBackend(
      String accessToken,
      HttpServerRequest req,
      HttpServerResponse response,
      BackendConfig backend
  ) {
    try {
      JWTClaimsSet claimsSet = backend
          .getJwtProcessor()
          .process(accessToken, (SecurityContext) null);
      if (LOGGER.isTraceEnabled()) {
        LOGGER.trace("Claims: {}", claimsSet.toJSONObject());
      }

      if (!matchClaims(claimsSet, backend.getClaimFilter())) {
        sendUnauthorized(response, "Claims do not match");
      }

      for (Entry<String, Object> claim : claimsSet.getClaims().entrySet()) {
        req
            .headers()
            .add(
                Optional
                    .ofNullable(backend.getHeaderPrefix())
                    .orElse(DEFAULT_HEADER_PREFIX)
                    + claim.getKey(),
                claimValueToString(claim.getValue()
                ));
      }
      LOGGER.debug("Sending request to reverse proxy");
      backend.getProxy().handle(req);

    } catch (Exception e) {
      sendUnauthorized(response, e.getMessage());
    }
  }

  private boolean matchClaims(JWTClaimsSet claimsSet, List<ClaimFilter> claimFilters) {
    if (claimFilters == null || claimFilters.isEmpty()) {
      return true;
    }
    if (claimsSet == null || claimFilters.isEmpty()) {
      return false;
    }
    for (ClaimFilter claimFilter : claimFilters) {
      try {
        String claimValue = claimsSet.getStringClaim(claimFilter.getKey());
        String filterValue = claimFilter.getValue();
        if (!claimFilter.getType().matches(claimValue, filterValue)) {
          return false;
        }
      } catch (ParseException e) {
        LOGGER.error(
            "Claim [{}] parsing failed, cause: {} - {}",
            claimFilter.getKey(),
            e.getClass().getSimpleName(),
            e.getMessage(),
            e
        );
      }
      return false;
    }
    return true;
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
      //if a config already exists and realm and backend values are the same, then just replace filters
      optionalExistingConfig
          .get()
          .setHeaderFilter(backendConfig.getHeaderFilter())
          .setClaimFilter(backendConfig.getClaimFilter());
    }
  }

  private void initHttpProxy(BackendConfig backendConfig) {
    backendConfig.setProxy(
        HttpProxy
            .reverseProxy(client)
            .origin(backendConfig.getBackendPort(), backendConfig.getBackendHost())
    );
  }

  private void sendUnauthorized(HttpServerResponse response, String error) {
    LOGGER.error("Authorization error: {}", error);
    response.setStatusCode(401).send("Unauthorized: " + error);
  }

  private void initTokenProcessor(BackendConfig config) throws GeneralException, IOException {
    // The OpenID provider issuer URL
    Issuer issuer = new Issuer(config.getRealmUrl());

    // Will resolve the OpenID provider metadata automatically
    OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(issuer);

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
        new JWTClaimsSet.Builder().issuer(opMetadata.getIssuer().getValue()).build(),
        new HashSet<>(List.of("sub", "typ", "iat"))));

    config.setJwtProcessor(jwtProcessor);
  }

  private static String claimValueToString(Object value) {
    return value.toString();
  }
}
