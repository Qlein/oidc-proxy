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

    Set<BackendKey> backendKeys = loader.addConfigMap(configMap);

    assertEquals(Set.of(new BackendKey("backend-a", "api"), new BackendKey("backend-a", "admin")),
        backendKeys);
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
  void removedConfigMapDataEntryRemovesOnlyMatchingBackendConfig() {
    ConfigMap initialConfigMap = new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .addToLabels("backendId", "backend-a")
        .addToLabels("type", "backendOidc")
        .endMetadata()
        .addToData("api", backendJson("/api", 9090))
        .addToData("admin", backendJson("/admin", 9091))
        .build();
    loader.addConfigMap(initialConfigMap);

    ConfigMap updatedConfigMap = new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .addToLabels("backendId", "backend-a")
        .addToLabels("type", "backendOidc")
        .endMetadata()
        .addToData("api", backendJson("/api", 9090))
        .build();
    registry.removeBackendsMissingFrom(loader.addConfigMap(updatedConfigMap));

    assertEquals(1, registry.getBackendConfigs().size());
    assertEquals("api", registry.getBackendConfigs().get(0).getConfigMapField());
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
    ConfigMap unlabeledConfigMap = new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .endMetadata()
        .build();

    assertTrue(loader.checkConfigMapLabels(matchingConfigMap));
    assertFalse(loader.checkConfigMapLabels(wrongTypeConfigMap));
    assertFalse(loader.checkConfigMapLabels(missingBackendConfigMap));
    assertFalse(loader.checkConfigMapLabels(unlabeledConfigMap));
  }

  @Test
  void addConfigMapIgnoresMissingData() {
    ConfigMap configMap = new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .addToLabels("backendId", "backend-a")
        .addToLabels("type", "backendOidc")
        .endMetadata()
        .build();

    assertTrue(loader.addConfigMap(configMap).isEmpty());
    assertTrue(registry.getBackendConfigs().isEmpty());
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
