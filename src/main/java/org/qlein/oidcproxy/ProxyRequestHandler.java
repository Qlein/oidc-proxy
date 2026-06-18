package org.qlein.oidcproxy;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.Optional;

class ProxyRequestHandler implements Handler<HttpServerRequest> {

  private static final Logger LOGGER = LoggerFactory.getLogger(ProxyRequestHandler.class);

  private final BackendRegistry backendRegistry;

  ProxyRequestHandler(BackendRegistry backendRegistry) {
    this.backendRegistry = backendRegistry;
  }

  @Override
  public void handle(HttpServerRequest req) {
    HttpServerResponse response = req.response();
    String authorizationHeaderValue = req.getHeader(HttpHeaders.AUTHORIZATION);

    if (authorizationHeaderValue == null) {
      RequestProcessor.sendUnauthorized(req, response, "Auth header missing");
      return;
    }
    if (!authorizationHeaderValue.startsWith(MainVerticle.BEARER_PREFIX)) {
      RequestProcessor.sendUnauthorized(req, response, "Bearer missing");
      return;
    }

    String accessToken = authorizationHeaderValue.substring(MainVerticle.BEARER_PREFIX.length());
    LOGGER.trace("Token: {}", accessToken);

    Optional<BackendConfig> matchingBackend = backendRegistry.findMatchingBackend(req);
    if (matchingBackend.isEmpty()) {
      RequestProcessor.sendUnauthorized(req, response, "Unknown instance");
      return;
    }

    LOGGER.trace(
        "Backend config with path prefix [{}] will be used to process request",
        matchingBackend.get().getPathPrefix()
    );
    RequestProcessor.processRequestWithBackend(accessToken, req, response, matchingBackend.get());
  }
}
