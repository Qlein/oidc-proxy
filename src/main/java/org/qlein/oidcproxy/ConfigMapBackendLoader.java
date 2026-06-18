package org.qlein.oidcproxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

class ConfigMapBackendLoader {

  static final String LABEL_BACKEND_ID = "backendId";
  static final String LABEL_TYPE = "type";
  static final String CONFIG_MAP_TYPE_OIDC = "backendOidc";

  private static final Logger LOGGER = LoggerFactory.getLogger(ConfigMapBackendLoader.class);

  private final BackendRegistry backendRegistry;
  private final JsonMapper jsonMapper = JsonMapper
      .builder()
      .enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
      .build();

  ConfigMapBackendLoader(BackendRegistry backendRegistry) {
    this.backendRegistry = backendRegistry;
  }

  void loadBackends(KubernetesClient kubernetesClient) {
    LOGGER.trace("Loading config maps");
    Set<BackendKey> foundBackends = kubernetesClient
        .configMaps()
        .list()
        .getItems()
        .stream()
        .filter(this::checkConfigMapLabels)
        .flatMap(configMap -> addConfigMap(configMap).stream())
        .collect(Collectors.toSet());

    backendRegistry.removeBackendsMissingFrom(foundBackends);
  }

  boolean checkConfigMapLabels(ConfigMap configMap) {
    Map<String, String> labels = getLabels(configMap);
    String backendId = labels.get(LABEL_BACKEND_ID);
    String type = labels.get(LABEL_TYPE);
    LOGGER.trace(
        "Checking config map {}, backend label: {}, type label: {}",
        getName(configMap),
        backendId,
        type
    );
    return backendId != null && CONFIG_MAP_TYPE_OIDC.equals(type);
  }

  Set<BackendKey> addConfigMap(ConfigMap configMap) {
    String backendId = getLabels(configMap).get(LABEL_BACKEND_ID);
    Set<BackendKey> foundBackends = new HashSet<>();
    for (Entry<String, String> configJsonEntry : getData(configMap).entrySet()) {
      BackendKey backendKey = new BackendKey(backendId, configJsonEntry.getKey());
      foundBackends.add(backendKey);
      try {
        backendRegistry.addOrUpdateBackend(
            jsonMapper
                .readValue(configJsonEntry.getValue(), BackendConfig.class)
                .setBackendId(backendId)
                .setConfigMapField(configJsonEntry.getKey())
        );
      } catch (JsonProcessingException e) {
        LOGGER.error(
            "Parsing of config map [{}] failed, cause: {} - {}",
            getName(configMap),
            e.getClass().getSimpleName(),
            e.getMessage(),
            e
        );
      }
    }
    return foundBackends;
  }

  private Map<String, String> getLabels(ConfigMap configMap) {
    return Optional
        .ofNullable(configMap.getMetadata())
        .map(ObjectMeta::getLabels)
        .orElse(Map.of());
  }

  private Map<String, String> getData(ConfigMap configMap) {
    return Optional
        .ofNullable(configMap.getData())
        .orElse(Map.of());
  }

  private String getName(ConfigMap configMap) {
    return Optional
        .ofNullable(configMap.getMetadata())
        .map(ObjectMeta::getName)
        .orElse(null);
  }
}
