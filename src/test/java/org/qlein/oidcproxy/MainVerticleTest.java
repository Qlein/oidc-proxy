package org.qlein.oidcproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpServerRequest;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MainVerticleTest {

  private MainVerticle verticle;

  @BeforeEach
  void init() throws Exception {
    verticle = new MainVerticle();
    setField("client", mock(HttpClient.class));
  }

  @Test
  void matchRequestRequiresPathAndConfiguredHeaders() throws Exception {
    BackendConfig backendConfig = backendConfig("backend-a", "api")
        .setPathPrefix(Set.of("/api"))
        .setHeaderFilter(Map.of("Host", "api.localhost"));

    assertTrue(matchRequest(request("/api/orders", "api.localhost"), backendConfig));
    assertFalse(matchRequest(request("/admin/orders", "api.localhost"), backendConfig));
    assertFalse(matchRequest(request("/api/orders", "admin.localhost"), backendConfig));
  }

  @Test
  void addOrUpdateBackendAddsInitializedBackend() throws Exception {
    BackendConfig backendConfig = backendConfig("backend-a", "api");

    verticle.addOrUpdateBackend(backendConfig);

    List<BackendConfig> backendConfigs = backendConfigs();
    assertEquals(1, backendConfigs.size());
    assertSame(backendConfig, backendConfigs.get(0));
    assertNotNull(backendConfig.getJwtProcessor());
    assertNotNull(backendConfig.getProxy());
  }

  @Test
  void addOrUpdateBackendUpdatesFiltersWithoutReinitializingUnchangedBackend() throws Exception {
    BackendConfig initialBackend = backendConfig("backend-a", "api")
        .setHeaderFilter(Map.of("Host", "api.localhost"))
        .setClaimFilter(List.of(ClaimFilterType.list_contains.get("groups", "/group1")));
    verticle.addOrUpdateBackend(initialBackend);
    Object initialJwtProcessor = initialBackend.getJwtProcessor();
    Object initialProxy = initialBackend.getProxy();

    BackendConfig updatedBackend = backendConfig("backend-a", "api")
        .setHeaderFilter(Map.of("Host", "admin.localhost"))
        .setClaimFilter(List.of(ClaimFilterType.string_contains.get("tenant", "internal")));

    verticle.addOrUpdateBackend(updatedBackend);

    List<BackendConfig> backendConfigs = backendConfigs();
    assertEquals(1, backendConfigs.size());
    assertSame(initialBackend, backendConfigs.get(0));
    assertSame(initialJwtProcessor, initialBackend.getJwtProcessor());
    assertSame(initialProxy, initialBackend.getProxy());
    assertEquals(Map.of("Host", "admin.localhost"), initialBackend.getHeaderFilter());
    assertEquals("tenant", initialBackend.getClaimFilter().get(0).getKey());
  }

  @Test
  void addOrUpdateBackendReplacesBackendWhenOriginChanges() throws Exception {
    BackendConfig initialBackend = backendConfig("backend-a", "api");
    verticle.addOrUpdateBackend(initialBackend);

    BackendConfig updatedBackend = backendConfig("backend-a", "api")
        .setBackendPort(9091);
    verticle.addOrUpdateBackend(updatedBackend);

    List<BackendConfig> backendConfigs = backendConfigs();
    assertEquals(1, backendConfigs.size());
    assertSame(updatedBackend, backendConfigs.get(0));
    assertNotSame(initialBackend, backendConfigs.get(0));
    assertNotNull(updatedBackend.getJwtProcessor());
    assertNotNull(updatedBackend.getProxy());
  }

  @Test
  void addConfigMapLoadsEachDataEntryWithBackendIdentity() throws Exception {
    ConfigMap configMap = new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .addToLabels("backendId", "backend-a")
        .addToLabels("type", "backendOidc")
        .endMetadata()
        .addToData("api", backendJson("/api", 9090))
        .addToData("admin", backendJson("/admin", 9091))
        .build();

    String backendId = addConfigMap(configMap);

    List<BackendConfig> backendConfigs = backendConfigs();
    assertEquals("backend-a", backendId);
    assertEquals(2, backendConfigs.size());
    assertEquals(Set.of("api", "admin"),
        Set.of(backendConfigs.get(0).getConfigMapField(), backendConfigs.get(1).getConfigMapField()));
    assertTrue(backendConfigs.stream().allMatch(config -> "backend-a".equals(config.getBackendId())));
  }

  @Test
  void checkConfigMapLabelsOnlyAcceptsBackendOidcMapsWithBackendId() throws Exception {
    ConfigMap matchingConfigMap = configMapWithLabels(Map.of(
        "backendId", "backend-a",
        "type", "backendOidc"
    ));
    ConfigMap wrongTypeConfigMap = configMapWithLabels(Map.of(
        "backendId", "backend-a",
        "type", "other"
    ));
    ConfigMap missingBackendConfigMap = configMapWithLabels(Map.of("type", "backendOidc"));

    assertTrue(checkConfigMapLabels(matchingConfigMap));
    assertFalse(checkConfigMapLabels(wrongTypeConfigMap));
    assertFalse(checkConfigMapLabels(missingBackendConfigMap));
  }

  private BackendConfig backendConfig(String backendId, String configMapField) {
    return new BackendConfig()
        .setBackendId(backendId)
        .setConfigMapField(configMapField)
        .setBackendHost("localhost")
        .setBackendPort(9090)
        .setPathPrefix(Set.of("/api"))
        .setRealmUrl(OidcProviderMock.getRealmUrl());
  }

  private HttpServerRequest request(String path, String host) {
    HttpServerRequest request = mock(HttpServerRequest.class);
    when(request.path()).thenReturn(path);
    when(request.getHeader("Host")).thenReturn(host);
    return request;
  }

  private String backendJson(String pathPrefix, int backendPort) {
    return """
        {
          "realmUrl": "%s",
          "pathPrefix": "%s",
          "backendHost": "localhost",
          "backendPort": %d
        }
        """.formatted(OidcProviderMock.getRealmUrl(), pathPrefix, backendPort);
  }

  private ConfigMap configMapWithLabels(Map<String, String> labels) {
    return new ConfigMapBuilder()
        .withNewMetadata()
        .withName("backend-config")
        .withLabels(labels)
        .endMetadata()
        .build();
  }

  @SuppressWarnings("unchecked")
  private List<BackendConfig> backendConfigs() throws Exception {
    Field field = MainVerticle.class.getDeclaredField("backendConfigs");
    field.setAccessible(true);
    return (List<BackendConfig>) field.get(verticle);
  }

  private void setField(String name, Object value) throws Exception {
    Field field = MainVerticle.class.getDeclaredField(name);
    field.setAccessible(true);
    field.set(verticle, value);
  }

  private boolean matchRequest(HttpServerRequest request, BackendConfig backendConfig) throws Exception {
    return invokePrivate("matchRequest", new Class<?>[]{HttpServerRequest.class, BackendConfig.class},
        request, backendConfig);
  }

  private String addConfigMap(ConfigMap configMap) throws Exception {
    return invokePrivate("addConfigMap", new Class<?>[]{ConfigMap.class}, configMap);
  }

  private boolean checkConfigMapLabels(ConfigMap configMap) throws Exception {
    return invokePrivate("checkConfigMapLabels", new Class<?>[]{ConfigMap.class}, configMap);
  }

  @SuppressWarnings("unchecked")
  private <T> T invokePrivate(String methodName, Class<?>[] parameterTypes, Object... args)
      throws Exception {
    Method method = MainVerticle.class.getDeclaredMethod(methodName, parameterTypes);
    method.setAccessible(true);
    try {
      return (T) method.invoke(verticle, args);
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof Exception exception) {
        throw exception;
      }
      throw e;
    }
  }
}
