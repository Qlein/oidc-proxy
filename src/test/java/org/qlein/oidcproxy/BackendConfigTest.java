package org.qlein.oidcproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class BackendConfigTest {

  @Test
  void testSerialization() throws JsonProcessingException {
    JsonMapper mapper = JsonMapper.builder().build();
    String json = mapper.writeValueAsString(
        new BackendConfig()
            .setHeaderFilter(Map.of(
                "Host", "api.localhost"
            ))
            .setBackendHost("localhost")
            .setPathPrefix("/api/admin")
            .setBackendPort(8080)
            .setRealmUrl("https://account.localhost/auth/realms/realmname")
            .setClaimFilter(List.of(
                ClaimFilterType.contains.get("group", "admin")
            ))
    );
    assertEquals(
        """
            {"realmUrl":"https://account.localhost/auth/realms/realmname","pathPrefix":"/api/admin","backendHost":"localhost","backendPort":8080,"headerFilter":{"Host":"api.localhost"},"claimFilter":[{"key":"group","value":"admin","type":"contains"}]}""",
        json
    );
  }
}