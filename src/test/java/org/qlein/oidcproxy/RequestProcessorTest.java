package org.qlein.oidcproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.GeneralException;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.impl.headers.HeadersMultiMap;
import io.vertx.httpproxy.HttpProxy;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class RequestProcessorTest {


  private static final String USER_ID = UUID.randomUUID().toString();

  private HeadersMultiMap headers;
  private HttpServerRequest request;
  private HttpServerResponse response;
  private HttpProxy proxy;
  private BackendConfig backendConfig;

  @BeforeEach
  void init() throws GeneralException, IOException {
    headers = new HeadersMultiMap();
    request = Mockito.mock(HttpServerRequest.class);
    Mockito.when(request.headers()).thenReturn(headers);

    response = Mockito.mock(HttpServerResponse.class);
    Mockito.when(response.setStatusCode(anyInt())).thenReturn(response);
    Mockito.when(response.putHeader(anyString(), anyString())).thenReturn(response);

    proxy = Mockito.mock(HttpProxy.class);

    backendConfig = new BackendConfig()
        .setHeaderFilter(Map.of(
            "Host", "api.localhost"
        ))
        .setBackendHost("localhost")
        .setPathPrefix("/api")
        .setBackendPort(8080)
        .setRealmUrl(OidcProviderMock.getRealmUrl())
        .setClaimFilter(List.of(
                ClaimFilterType.list_contains.get("groups", "/group1")
            )
        )
        .setProxy(proxy);
    MainVerticle.initTokenProcessor(backendConfig);
  }

  @Test
  void testProcessRequestWithBackend() throws JOSEException {
    String accessToken = OidcProviderMock.getAccessToken(USER_ID, List.of("/group1", "/group2"));

    RequestProcessor.processRequestWithBackend(
        accessToken,
        request,
        response,
        backendConfig
    );
    assertEquals(USER_ID, headers.get("X-auth-sub"));
    assertEquals("[\"/group1\",\"/group2\"]", headers.get("X-auth-groups"));
    Mockito.verify(proxy, Mockito.times(1)).handle(request);
  }

  @Test
  void testRejectRequestWithWrongGroup() throws JOSEException {
    String accessToken = OidcProviderMock.getAccessToken(USER_ID, List.of("/group0"));

    RequestProcessor.processRequestWithBackend(
        accessToken,
        request,
        response,
        backendConfig
    );
    Mockito.verifyNoInteractions(proxy);
  }

  @Test
  void testSimpleType() {
    assertTrue(RequestProcessor.isSimpleType(""));
    assertTrue(RequestProcessor.isSimpleType(10));
    assertTrue(RequestProcessor.isSimpleType(true));
  }
}