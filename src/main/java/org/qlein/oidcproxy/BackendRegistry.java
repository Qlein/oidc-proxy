package org.qlein.oidcproxy;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Collectors;

class BackendRegistry {

  private static final Logger LOGGER = LoggerFactory.getLogger(BackendRegistry.class);

  private final BackendInitializer backendInitializer;
  private final List<BackendConfig> backendConfigs = new Vector<>();

  BackendRegistry(BackendInitializer backendInitializer) {
    this.backendInitializer = backendInitializer;
  }

  List<BackendConfig> getBackendConfigs() {
    return backendConfigs;
  }

  Optional<BackendConfig> findMatchingBackend(HttpServerRequest req) {
    return backendConfigs
        .stream()
        .filter(config -> matchRequest(req, config))
        .findFirst();
  }

  boolean matchRequest(HttpServerRequest req, BackendConfig backendConfig) {
    LOGGER.trace(
        "Matching request to host [{}] and path [{}] against config with path prefix [{}]",
        req.getHeader("Host"),
        req.path(),
        backendConfig.getPathPrefix()
    );
    boolean pathMatches = backendConfig.matchesPath(req.path());

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

  void addOrUpdateBackend(BackendConfig backendConfig) {
    Optional<BackendConfig> optionalExistingConfig = backendConfigs
        .stream()
        .filter(existingConfig -> existingConfig.getBackendId().equals(backendConfig.getBackendId()) &&
            existingConfig.getConfigMapField().equals(backendConfig.getConfigMapField()))
        .findFirst();

    boolean initRequired = optionalExistingConfig
        .map(existingConfig -> !backendConfig.sameRealmAndBackend(existingConfig))
        .orElse(true);

    if (initRequired) {
      addInitializedBackend(backendConfig, optionalExistingConfig);
    } else {
      updateFilters(backendConfig, optionalExistingConfig.get());
    }
  }

  void removeBackendsMissingFrom(Set<String> foundBackends) {
    backendConfigs
        .stream()
        .filter(backendConfig -> !foundBackends.contains(backendConfig.getBackendId()))
        .collect(Collectors.toSet())
        .forEach(this::removeBackend);
  }

  private void addInitializedBackend(
      BackendConfig backendConfig,
      Optional<BackendConfig> optionalExistingConfig
  ) {
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
      backendInitializer.initialize(backendConfig);
    } catch (Throwable e) {
      LOGGER.error(
          "Backend init failed, cause: {} - {}",
          e.getClass().getSimpleName(),
          e.getMessage(),
          e
      );
      return;
    }

    optionalExistingConfig.ifPresent(backendConfigs::remove);
    backendConfigs.add(backendConfig);
  }

  private void updateFilters(BackendConfig newBackendConfig, BackendConfig existingBackendConfig) {
    LOGGER.trace(
        "Updating backend [{}:{}] => {}:{}",
        newBackendConfig.getBackendId(),
        newBackendConfig.getPathPrefix(),
        newBackendConfig.getBackendHost(),
        newBackendConfig.getBackendPort()
    );

    existingBackendConfig
        .setHeaderFilter(newBackendConfig.getHeaderFilter())
        .setClaimFilter(newBackendConfig.getClaimFilter());
  }

  private void removeBackend(BackendConfig backendConfig) {
    LOGGER.info(
        "Removing backend [{}:{}]",
        backendConfig.getBackendId(),
        backendConfig.getPathPrefix()
    );
    backendConfigs.remove(backendConfig);
  }
}
