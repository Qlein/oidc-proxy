package org.qlein.oidcproxy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.io.IOException;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import net.minidev.json.JSONObject;

class OidcTokenProcessorFactory {

  private static final Logger LOGGER = LoggerFactory.getLogger(OidcTokenProcessorFactory.class);
  private static final int OIDC_HTTP_TIMEOUT_MS = 20000;

  static OIDCProviderMetadata resolve(final BackendConfig backendConfig)
      throws GeneralException, IOException {
    Issuer issuer = new Issuer(
        Optional
            .ofNullable(backendConfig.getRealmInternalUrl())
            .orElse(backendConfig.getRealmUrl())
    );

    URL configURL = OIDCProviderMetadata.resolveURL(issuer);

    HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, configURL);
    httpRequest.setConnectTimeout(OIDC_HTTP_TIMEOUT_MS);
    httpRequest.setReadTimeout(OIDC_HTTP_TIMEOUT_MS);
    if (HttpProxyProvider.isHttpProxyConfigured()) {
      httpRequest.setProxy(HttpProxyProvider.getHttpProxy());
    }

    HTTPResponse httpResponse = httpRequest.send();

    if (httpResponse.getStatusCode() != 200) {
      throw new IOException("Couldn't download OpenID Provider metadata from " + configURL +
          ": Status code " + httpResponse.getStatusCode());
    }

    JSONObject jsonObject = JSONObjectUtils.parse(httpResponse.getBody());
    if (backendConfig.getRealmInternalUrl() != null) {
      jsonObject.put(
          "jwks_uri",
          ((String) jsonObject.get("jwks_uri"))
              .replaceAll(
                  backendConfig.getRealmUrl(),
                  backendConfig.getRealmInternalUrl()
              )
      );
    }

    return OIDCProviderMetadata.parse(jsonObject);
  }

  static void initTokenProcessor(BackendConfig config) throws GeneralException, IOException {
    OIDCProviderMetadata opMetadata = resolve(config);
    LOGGER.debug("OIDC provider meta data: {}", opMetadata.toJSONObject());

    DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));

    DefaultResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
        OIDC_HTTP_TIMEOUT_MS,
        OIDC_HTTP_TIMEOUT_MS,
        RemoteJWKSet.resolveDefaultHTTPSizeLimit()
    );
    if (HttpProxyProvider.isHttpProxyConfigured()) {
      jwkSetRetriever.setProxy(HttpProxyProvider.getHttpProxy());
    }

    JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(
        opMetadata.getJWKSetURI().toURL(),
        jwkSetRetriever
    );

    JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
        new HashSet<>(opMetadata.getIDTokenJWSAlgs()),
        keySource
    );

    jwtProcessor.setJWSKeySelector(keySelector);
    jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
        new JWTClaimsSet.Builder().build(),
        new HashSet<>(List.of("sub", "typ", "iat"))
    ));

    config.setJwtProcessor(jwtProcessor);
  }
}
