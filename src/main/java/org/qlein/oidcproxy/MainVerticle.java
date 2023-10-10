package org.qlein.oidcproxy;

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
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.httpproxy.HttpProxy;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;

public class MainVerticle extends AbstractVerticle {

  protected static final int SLEEP_DURATION = 1900;
  private final Logger LOGGER = LoggerFactory.getLogger(MainVerticle.class);

  public static final String BEARER_PREFIX = "Bearer ";
  public static final String DEFAULT_HEADER_PREFIX = "X-auth-";
  public static final String OIDC_PROXY_BACKEND_PORT = "OIDC_PROXY_BACKEND_PORT";
  public static final String OIDC_PROXY_BACKEND_HOST = "OIDC_PROXY_BACKEND_HOST";
  public static final String OIDC_PROXY_PORT = "OIDC_PROXY_PORT";
  public static final String OIDC_PROXY_REALM_URL = "OIDC_PROXY_REALM_URL";
  public static final String OIDC_PROXY_HEADER_PREFIX = "OIDC_PROXY_HEADER_PREFIX";
  private static final String[] REQUIRED_ENV_VARS = new String[]{
      OIDC_PROXY_BACKEND_HOST,
      OIDC_PROXY_BACKEND_PORT,
      OIDC_PROXY_PORT,
      OIDC_PROXY_REALM_URL
  };

  private HttpProxy proxy;
  private DefaultJWTProcessor<SecurityContext> jwtProcessor;
  private int proxyPort;
  private String realmUrl;
  private String headerPrefix;
  private int backendPort;
  private String backendHost;
  private ConfigRetriever myConfigRetriver;
  private HttpClient client;

  @Override
  public void init(Vertx vertx, Context context) {
    super.init(vertx, context);

    ConfigStoreOptions jsonEnvConfig = new ConfigStoreOptions()
        .setType("env")
        .setConfig(
            new JsonObject()
                .put(
                    "keys",
                    new JsonArray()
                        .add(OIDC_PROXY_BACKEND_PORT)
                        .add(OIDC_PROXY_BACKEND_HOST)
                        .add(OIDC_PROXY_PORT)
                        .add(OIDC_PROXY_REALM_URL)
                        .add(OIDC_PROXY_HEADER_PREFIX)
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

              boolean tokenProcessorInitialized = false;
              int tokenProcessorInitCounter = 0;
              
              while (tokenProcessorInitCounter < 10 && !tokenProcessorInitialized) {
                tokenProcessorInitCounter++;
                try {
                  initTokenProcessor();
                  tokenProcessorInitialized = true;
                } catch (Throwable e) {
                  LOGGER.error(
                      "Token processor init failed with cause [{}], sleeping {}s before retry",
                      e.getMessage(),
                      SLEEP_DURATION
                  );
                  sleep(1900);
                }
              }
              if (!tokenProcessorInitialized) {
                startPromise.fail("Token processor initialization failed mutiple times");
                return;
              }

              initProxy(startPromise);
            }
        )
        .onFailure(
            e -> startPromise.fail("Can't load config: " + e.getMessage())
        );
  }

  private void sleep(int millis) {
    try {
      Thread.sleep(millis);
    } catch (Throwable e) {
    }
  }

  private boolean loadConfigValues(JsonObject asyncResults) {
    boolean configIsValid = true;
    for (String requiredEnvVar : REQUIRED_ENV_VARS) {
      if (!asyncResults.containsKey(requiredEnvVar)) {
        configIsValid = false;
        LOGGER.error("Missing env variable: {}", requiredEnvVar);
      }
    }
    if (!configIsValid) {
      return false;
    }
    LOGGER.info("Loaded config values: {}", asyncResults.encodePrettily());

    proxyPort = asyncResults.getInteger(OIDC_PROXY_PORT);
    realmUrl = asyncResults.getString(OIDC_PROXY_REALM_URL);
    backendPort = asyncResults.getInteger(OIDC_PROXY_BACKEND_PORT);
    backendHost = asyncResults.getString(OIDC_PROXY_BACKEND_HOST);
    headerPrefix = asyncResults.getString(OIDC_PROXY_HEADER_PREFIX, DEFAULT_HEADER_PREFIX);

    return true;
  }

  private void initProxy(Promise<Void> startPromise) {
    proxy = HttpProxy
        .reverseProxy(client)
        .origin(backendPort, backendHost);

    vertx
        .createHttpServer()
        .requestHandler(req -> {

          HttpServerResponse response = req.response();

          String accessToken = req.getHeader(HttpHeaders.AUTHORIZATION);

          if (accessToken == null) {
            sendUnauthorized(response, "Auth header missing");
          } else if (!accessToken.startsWith(BEARER_PREFIX)) {
            sendUnauthorized(response, "Bearer missing");
          } else {
            accessToken = accessToken.substring(BEARER_PREFIX.length());
            LOGGER.trace("Token: {}", accessToken);
            try {
              JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, (SecurityContext) null);
              LOGGER.trace("Claims: {}", claimsSet.toJSONObject());
              for (Entry<String, Object> claim : claimsSet.getClaims().entrySet()) {
                req.headers()
                    .add(headerPrefix + claim.getKey(), claimValueToString(claim.getValue()));
              }
              proxy.handle(req);
            } catch (Exception e) {
              sendUnauthorized(response, e.getMessage());
            }
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

  private void sendUnauthorized(HttpServerResponse response, String error) {
    LOGGER.error("Authorization error: {}", error);
    response.setStatusCode(401).send("Unauthorized: " + error);
  }

  private void initTokenProcessor() throws GeneralException, IOException {
    // The OpenID provider issuer URL
    Issuer issuer = new Issuer(realmUrl);

    // Will resolve the OpenID provider metadata automatically
    OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(issuer);

    // Print the metadata
    LOGGER.debug("OIDC provider meta data: {}", opMetadata.toJSONObject());

    jwtProcessor = new DefaultJWTProcessor<>();

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
  }

  private static String claimValueToString(Object value) {
    return value.toString();
  }
}
