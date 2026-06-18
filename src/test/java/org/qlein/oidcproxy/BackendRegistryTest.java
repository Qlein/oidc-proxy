package org.qlein.oidcproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.httpproxy.HttpProxy;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BackendRegistryTest {

  private BackendRegistry registry;

  @BeforeEach
  void init() {
    registry = new BackendRegistry(
        backendConfig -> backendConfig.setProxy(mock(HttpProxy.class))
    );
  }

  @Test
  void matchRequestRequiresPathAndConfiguredHeaders() {
    BackendConfig backendConfig = backendConfig("backend-a", "api")
        .setPathPrefix(Set.of("/api"))
        .setHeaderFilter(Map.of("Host", "api.localhost"));

    assertTrue(registry.matchRequest(request("/api/orders", "api.localhost"), backendConfig));
    assertFalse(registry.matchRequest(request("/admin/orders", "api.localhost"), backendConfig));
    assertFalse(registry.matchRequest(request("/api/orders", "admin.localhost"), backendConfig));
  }

  @Test
  void addOrUpdateBackendAddsInitializedBackend() {
    BackendConfig backendConfig = backendConfig("backend-a", "api");

    registry.addOrUpdateBackend(backendConfig);

    List<BackendConfig> backendConfigs = registry.getBackendConfigs();
    assertEquals(1, backendConfigs.size());
    assertSame(backendConfig, backendConfigs.get(0));
    assertTrue(backendConfig.getProxy() != null);
  }

  @Test
  void addOrUpdateBackendUpdatesFiltersWithoutReinitializingUnchangedBackend() {
    BackendConfig initialBackend = backendConfig("backend-a", "api")
        .setHeaderFilter(Map.of("Host", "api.localhost"))
        .setClaimFilter(List.of(ClaimFilterType.list_contains.get("groups", "/group1")));
    registry.addOrUpdateBackend(initialBackend);
    Object initialProxy = initialBackend.getProxy();

    BackendConfig updatedBackend = backendConfig("backend-a", "api")
        .setHeaderFilter(Map.of("Host", "admin.localhost"))
        .setClaimFilter(List.of(ClaimFilterType.string_contains.get("tenant", "internal")));

    registry.addOrUpdateBackend(updatedBackend);

    List<BackendConfig> backendConfigs = registry.getBackendConfigs();
    assertEquals(1, backendConfigs.size());
    assertSame(initialBackend, backendConfigs.get(0));
    assertSame(initialProxy, initialBackend.getProxy());
    assertEquals(Map.of("Host", "admin.localhost"), initialBackend.getHeaderFilter());
    assertEquals("tenant", initialBackend.getClaimFilter().get(0).getKey());
  }

  @Test
  void addOrUpdateBackendReplacesBackendWhenOriginChanges() {
    BackendConfig initialBackend = backendConfig("backend-a", "api");
    registry.addOrUpdateBackend(initialBackend);

    BackendConfig updatedBackend = backendConfig("backend-a", "api")
        .setBackendPort(9091);
    registry.addOrUpdateBackend(updatedBackend);

    List<BackendConfig> backendConfigs = registry.getBackendConfigs();
    assertEquals(1, backendConfigs.size());
    assertSame(updatedBackend, backendConfigs.get(0));
    assertNotSame(initialBackend, backendConfigs.get(0));
    assertTrue(updatedBackend.getProxy() != null);
  }

  @Test
  void removeBackendsMissingFromDeletesStaleBackendConfigs() {
    registry.addOrUpdateBackend(backendConfig("backend-a", "api"));
    registry.addOrUpdateBackend(backendConfig("backend-b", "api"));

    registry.removeBackendsMissingFrom(Set.of("backend-a"));

    assertEquals(1, registry.getBackendConfigs().size());
    assertEquals("backend-a", registry.getBackendConfigs().get(0).getBackendId());
  }

  private BackendConfig backendConfig(String backendId, String configMapField) {
    return new BackendConfig()
        .setBackendId(backendId)
        .setConfigMapField(configMapField)
        .setBackendHost("localhost")
        .setBackendPort(9090)
        .setPathPrefix(Set.of("/api"))
        .setRealmUrl("http://localhost:1089");
  }

  private HttpServerRequest request(String path, String host) {
    HttpServerRequest request = mock(HttpServerRequest.class);
    when(request.path()).thenReturn(path);
    when(request.getHeader("Host")).thenReturn(host);
    return request;
  }
}
