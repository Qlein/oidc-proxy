package org.qlein.oidcproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.vertx.httpproxy.HttpProxy;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ConfigMapBackendLoaderTest {

  private BackendRegistry registry;
  private ConfigMapBackendLoader loader;

  @BeforeEach
  void init() {
    registry = new BackendRegistry(
        backendConfig -> backendConfig.setProxy(mock(HttpProxy.class))
    );
    loader = new ConfigMapBackendLoader(registry);
  }

  @Test
  void addConfigMapLoadsEachDataEntryWithBackendIdentity() {
    ConfigMap configMap = new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .addToLabels("backendId", "backend-a")
        .addToLabels("type", "backendOidc")
        .endMetadata()
        .addToData("api", backendJson("/api", 9090))
        .addToData("admin", backendJson("/admin", 9091))
        .build();

    String backendId = loader.addConfigMap(configMap);

    assertEquals("backend-a", backendId);
    assertEquals(2, registry.getBackendConfigs().size());
    assertEquals(
        Set.of("api", "admin"),
        Set.of(
            registry.getBackendConfigs().get(0).getConfigMapField(),
            registry.getBackendConfigs().get(1).getConfigMapField()
        )
    );
    assertTrue(registry
        .getBackendConfigs()
        .stream()
        .allMatch(config -> "backend-a".equals(config.getBackendId())));
  }

  @Test
  void checkConfigMapLabelsOnlyAcceptsBackendOidcMapsWithBackendId() {
    ConfigMap matchingConfigMap = configMapWithLabels(Map.of(
        "backendId", "backend-a",
        "type", "backendOidc"
    ));
    ConfigMap wrongTypeConfigMap = configMapWithLabels(Map.of(
        "backendId", "backend-a",
        "type", "other"
    ));
    ConfigMap missingBackendConfigMap = configMapWithLabels(Map.of("type", "backendOidc"));

    assertTrue(loader.checkConfigMapLabels(matchingConfigMap));
    assertFalse(loader.checkConfigMapLabels(wrongTypeConfigMap));
    assertFalse(loader.checkConfigMapLabels(missingBackendConfigMap));
  }

  private String backendJson(String pathPrefix, int backendPort) {
    return """
        {
          "realmUrl": "http://localhost:1089",
          "pathPrefix": "%s",
          "backendHost": "localhost",
          "backendPort": %d
        }
        """.formatted(pathPrefix, backendPort);
  }

  private ConfigMap configMapWithLabels(Map<String, String> labels) {
    return new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .withLabels(labels)
        .endMetadata()
        .build();
  }
}
