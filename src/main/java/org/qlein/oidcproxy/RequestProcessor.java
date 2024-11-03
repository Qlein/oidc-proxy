package org.qlein.oidcproxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;

public class RequestProcessor {

  private static final Logger LOGGER = LoggerFactory.getLogger(RequestProcessor.class);
  private static final JsonMapper jsonMapper = JsonMapper.builder().build();

  static void processRequestWithBackend(
      String accessToken,
      HttpServerRequest req,
      HttpServerResponse response,
      BackendConfig backend
  ) {
    try {
      JWTClaimsSet claimsSet = backend
          .getJwtProcessor()
          .process(accessToken, (SecurityContext) null);
      if (LOGGER.isTraceEnabled()) {
        LOGGER.trace("Claims: {}", claimsSet.toJSONObject());
      }

      if (!matchClaims(claimsSet, backend.getClaimFilter())) {
        sendUnauthorized(response, "Claims do not match");
        return;
      }

      String headerPrefix = Optional
          .ofNullable(backend.getHeaderPrefix())
          .orElse(MainVerticle.DEFAULT_HEADER_PREFIX);
      for (Entry<String, Object> claim : claimsSet.getClaims().entrySet()) {
        req
            .headers()
            .add(
                headerPrefix
                    + claim.getKey(),
                claimValueToString(claim.getValue()
                ));
      }
      LOGGER.debug("Sending request to reverse proxy");
      backend.getProxy().handle(req);

    } catch (Exception e) {
      LOGGER.error(
          "Processing request failed, cause: {} - {}",
          e.getClass().getName(),
          e.getMessage(),
          e);
      sendUnauthorized(response, e.getMessage());
    }
  }

  private static boolean matchClaims(JWTClaimsSet claimsSet, List<ClaimFilter> claimFilters) {
    if (claimFilters == null || claimFilters.isEmpty()) {
      return true;
    }
    if (claimsSet == null || claimFilters.isEmpty()) {
      return false;
    }
    for (ClaimFilter claimFilter : claimFilters) {
      Object claimValue = null;
      try {
        claimValue = claimsSet.getClaim(claimFilter.getKey());
        if (claimValue == null) {
          LOGGER.debug(
              "Required claim [{}:{}] is null",
              claimFilter.getKey(),
              claimValue
          );
          return false;
        }
        String filterValue = claimFilter.getValue();
        if (!claimFilter.getType().matches(claimValue, filterValue)) {
          LOGGER.debug(
              "Claim [{}:{}] does not matches filter [{}:{}]",
              claimFilter.getKey(),
              claimValue,
              claimFilter.getType().name(),
              claimFilter.getValue()
          );
          return false;
        }
      } catch (Exception e) {
        LOGGER.error(
            "Claim [{}:{}] processing with filter [{}] failed, cause: {} - {}",
            claimFilter.getKey(),
            claimValue,
            claimFilter.getValue(),
            e.getClass().getSimpleName(),
            e.getMessage(),
            e
        );
        return false;
      }
    }
    return true;
  }

  static void sendUnauthorized(HttpServerResponse response, String error) {
    LOGGER.error("Authorization error: {}", error);
    response.setStatusCode(401).send("Unauthorized: " + error);
  }

  private static String claimValueToString(Object value) {
    if (isSimpleType(value)) {
      return value.toString();
    }
    try {
      return jsonMapper.writeValueAsString(value);
    } catch (JsonProcessingException e) {
      return value.toString();
    }
  }

  static boolean isSimpleType(Object value) {
    return value instanceof String ||
        value instanceof Integer ||
        value instanceof Long ||
        value instanceof Boolean ||
        value instanceof Float ||
        value instanceof Double;
  }

}
