package org.qlein.oidcproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
            .setPathPrefix(Set.of("/api/admin"))
            .setBackendPort(8080)
            .setRealmUrl("https://account.localhost/auth/realms/realmname")
            .setClaimFilter(List.of(
                ClaimFilterType.string_contains.get("group", "admin")
            ))
    );
    assertEquals(
        """
            {"realmUrl":"https://account.localhost/auth/realms/realmname","realmInternalUrl":null,"headerPrefix":null,"pathPrefix":["/api/admin"],"backendHost":"localhost","backendPort":8080,"headerFilter":{"Host":"api.localhost"},"claimFilter":[{"key":"group","value":"admin","type":"string_contains"}]}""",
        json
    );
  }

  @Test
  void testSingleValuePathPrefixDeserialization() throws JsonProcessingException {
    String json = """
        {"realmUrl":"https://account.localhost/auth/realms/realmname","realmInternalUrl":null,"headerPrefix":null,"pathPrefix":"/api/admin","backendHost":"localhost","backendPort":8080,"headerFilter":{"Host":"api.localhost"},"claimFilter":[{"key":"group","value":"admin","type":"string_contains"}]}
        """;
    JsonMapper mapper = JsonMapper
        .builder()
        .enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
        .build();
    BackendConfig config = mapper.readValue(json, BackendConfig.class);
    assertEquals(
        Set.of("/api/admin"),
        config.getPathPrefix()
    );
  }
}