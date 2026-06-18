package org.qlein.oidcproxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.Map;
import java.util.Map.Entry;
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
    Set<String> foundBackends = kubernetesClient
        .configMaps()
        .list()
        .getItems()
        .stream()
        .filter(this::checkConfigMapLabels)
        .map(this::addConfigMap)
        .collect(Collectors.toSet());

    backendRegistry.removeBackendsMissingFrom(foundBackends);
  }

  boolean checkConfigMapLabels(ConfigMap configMap) {
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

  String addConfigMap(ConfigMap configMap) {
    String backendId = configMap.getMetadata().getLabels().get(LABEL_BACKEND_ID);
    for (Entry<String, String> configJsonEntry : configMap.getData().entrySet()) {
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
            configMap.getMetadata().getName(),
            e.getClass().getSimpleName(),
            e.getMessage(),
            e
        );
      }
    }
    return backendId;
  }
}
