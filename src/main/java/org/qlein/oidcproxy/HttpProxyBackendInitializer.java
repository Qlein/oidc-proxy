package org.qlein.oidcproxy;

import io.vertx.core.http.HttpClient;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.httpproxy.HttpProxy;

class HttpProxyBackendInitializer implements BackendInitializer {

  private static final Logger LOGGER = LoggerFactory.getLogger(HttpProxyBackendInitializer.class);

  private final HttpClient client;

  HttpProxyBackendInitializer(HttpClient client) {
    this.client = client;
  }

  @Override
  public void initialize(BackendConfig backendConfig) throws Exception {
    OidcTokenProcessorFactory.initTokenProcessor(backendConfig);
    initHttpProxy(backendConfig);
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
}
