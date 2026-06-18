package org.qlein.oidcproxy;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.tracing.TracingPolicy;
import java.io.IOException;

public class MainVerticle extends AbstractVerticle {

  private static final Logger LOGGER = LoggerFactory.getLogger(MainVerticle.class);

  public static final String BEARER_PREFIX = "Bearer ";
  public static final String DEFAULT_HEADER_PREFIX = "X-auth-";
  public static final int DEFAULT_PROXY_PORT = 8080;
  public static final String OIDC_PROXY_PORT = "OIDC_PROXY_PORT";

  private int proxyPort;

  private ConfigRetriever myConfigRetriver;
  private KubernetesClient kubernetesClient;
  private HttpClient httpClient;
  private HttpServer httpServer;
  private BackendRegistry backendRegistry;
  private ConfigMapBackendLoader configMapBackendLoader;
  private Long backendRefreshTimerId;

  @Override
  public void init(Vertx vertx, Context context) {
    super.init(vertx, context);

    initKubernetesClient();
    initConfigRetriever(vertx);
    initBackendRegistry(vertx);
  }

  private void initKubernetesClient() {
    kubernetesClient = new KubernetesClientBuilder().build();
  }

  private void initConfigRetriever(Vertx vertx) {
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
  }

  private void initBackendRegistry(Vertx vertx) {
    httpClient = vertx.createHttpClient(
        new HttpClientOptions()
            .setMaxInitialLineLength(10000)
            .setTracingPolicy(TracingPolicy.PROPAGATE)
            .setLogActivity(true)
    );
    backendRegistry = new BackendRegistry(new HttpProxyBackendInitializer(httpClient));
    configMapBackendLoader = new ConfigMapBackendLoader(backendRegistry);
  }

  @Override
  public void start(Promise<Void> startPromise) {
    myConfigRetriver
        .getConfig()
        .onSuccess(asyncResults -> {
          if (!loadConfigValues(asyncResults)) {
            startPromise.fail("Invalid or incomplete config, missing one or more env variables");
            return;
          }
          initProxy(startPromise);
          backendRefreshTimerId = vertx.setPeriodic(1000L, 10000L, this::loadBackends);
        })
        .onFailure(e -> startPromise.fail("Can't load config: " + e.getMessage()));
  }

  @Override
  public void stop(Promise<Void> stopPromise) {
    LOGGER.info("Stopping oidc-proxy");

    if (backendRefreshTimerId != null) {
      vertx.cancelTimer(backendRefreshTimerId);
      backendRefreshTimerId = null;
    }

    if (myConfigRetriver != null) {
      myConfigRetriver.close();
    }

    Future<Void> httpServerClose = httpServer != null
        ? httpServer.close()
        : Future.succeededFuture();
    Future<Void> httpClientClose = httpClient != null
        ? httpClient.close()
        : Future.succeededFuture();

    Future
        .all(httpServerClose, httpClientClose)
        .onComplete(closeResult -> {
          if (kubernetesClient != null) {
            kubernetesClient.close();
          }

          if (closeResult.succeeded()) {
            LOGGER.info("oidc-proxy stopped");
            stopPromise.complete();
          } else {
            stopPromise.fail(closeResult.cause());
          }
        });
  }

  private void loadBackends(Long timerId) {
    configMapBackendLoader.loadBackends(kubernetesClient);
  }

  private boolean loadConfigValues(JsonObject asyncResults) {
    LOGGER.info("Loaded config values: {}", asyncResults.encodePrettily());
    proxyPort = asyncResults.getInteger(OIDC_PROXY_PORT, DEFAULT_PROXY_PORT);
    return true;
  }

  private void initProxy(Promise<Void> startPromise) {
    httpServer = vertx
        .createHttpServer()
        .requestHandler(new ProxyRequestHandler(backendRegistry))
        .listen(proxyPort, http -> {
          if (http.succeeded()) {
            startPromise.complete();
            LOGGER.info("HTTP server started on port {}", proxyPort);
          } else {
            startPromise.fail(http.cause());
          }
        });
  }

  public static OIDCProviderMetadata resolve(final BackendConfig backendConfig)
      throws GeneralException, IOException {
    return OidcTokenProcessorFactory.resolve(backendConfig);
  }

  public static void initTokenProcessor(BackendConfig config) throws GeneralException, IOException {
    OidcTokenProcessorFactory.initTokenProcessor(config);
  }
}
