package org.qlein.oidcproxy;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.List;

public class OidcProviderMock {

  private static final int PORT = 1089;
  private static final WireMockServer wireMockServer = new WireMockServer(PORT);
  public static final PrivateKey PRIVATE_KEY;

  private static final String ISSUER_CONFIG = """
      '{'
        "issuer": "http://localhost:{0}",
        "authorization_endpoint": "http://localhost:{0}/protocol/openid-connect/auth",
        "token_endpoint": "http://localhost:{0}/protocol/openid-connect/token",
        "introspection_endpoint": "http://localhost:{0}/protocol/openid-connect/token/introspect",
        "userinfo_endpoint": "http://localhost:{0}/protocol/openid-connect/userinfo",
        "end_session_endpoint": "http://localhost:{0}/protocol/openid-connect/logout",
        "frontchannel_logout_session_supported": true,
        "frontchannel_logout_supported": true,
        "jwks_uri": "http://localhost:{0}/protocol/openid-connect/certs",
        "check_session_iframe": "http://localhost:{0}/protocol/openid-connect/login-status-iframe.html",
        "grant_types_supported": [
          "authorization_code",
          "implicit",
          "refresh_token",
          "password",
          "client_credentials",
          "urn:openid:params:grant-type:ciba",
          "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "acr_values_supported": [
          "0",
          "1"
        ],
        "response_types_supported": [
          "code",
          "none",
          "id_token",
          "token",
          "id_token token",
          "code id_token",
          "code token",
          "code id_token token"
        ],
        "subject_types_supported": [
          "public",
          "pairwise"
        ],
        "id_token_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512"
        ],
        "id_token_encryption_alg_values_supported": [
          "ECDH-ES+A256KW",
          "ECDH-ES+A192KW",
          "ECDH-ES+A128KW",
          "RSA-OAEP",
          "RSA-OAEP-256",
          "RSA1_5",
          "ECDH-ES"
        ],
        "id_token_encryption_enc_values_supported": [
          "A256GCM",
          "A192GCM",
          "A128GCM",
          "A128CBC-HS256",
          "A192CBC-HS384",
          "A256CBC-HS512"
        ],
        "userinfo_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512",
          "none"
        ],
        "userinfo_encryption_alg_values_supported": [
          "ECDH-ES+A256KW",
          "ECDH-ES+A192KW",
          "ECDH-ES+A128KW",
          "RSA-OAEP",
          "RSA-OAEP-256",
          "RSA1_5",
          "ECDH-ES"
        ],
        "userinfo_encryption_enc_values_supported": [
          "A256GCM",
          "A192GCM",
          "A128GCM",
          "A128CBC-HS256",
          "A192CBC-HS384",
          "A256CBC-HS512"
        ],
        "request_object_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512",
          "none"
        ],
        "request_object_encryption_alg_values_supported": [
          "ECDH-ES+A256KW",
          "ECDH-ES+A192KW",
          "ECDH-ES+A128KW",
          "RSA-OAEP",
          "RSA-OAEP-256",
          "RSA1_5",
          "ECDH-ES"
        ],
        "request_object_encryption_enc_values_supported": [
          "A256GCM",
          "A192GCM",
          "A128GCM",
          "A128CBC-HS256",
          "A192CBC-HS384",
          "A256CBC-HS512"
        ],
        "response_modes_supported": [
          "query",
          "fragment",
          "form_post",
          "query.jwt",
          "fragment.jwt",
          "form_post.jwt",
          "jwt"
        ],
        "registration_endpoint": "http://localhost:{0}/clients-registrations/openid-connect",
        "token_endpoint_auth_methods_supported": [
          "private_key_jwt",
          "client_secret_basic",
          "client_secret_post",
          "tls_client_auth",
          "client_secret_jwt"
        ],
        "token_endpoint_auth_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512"
        ],
        "introspection_endpoint_auth_methods_supported": [
          "private_key_jwt",
          "client_secret_basic",
          "client_secret_post",
          "tls_client_auth",
          "client_secret_jwt"
        ],
        "introspection_endpoint_auth_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512"
        ],
        "authorization_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512"
        ],
        "authorization_encryption_alg_values_supported": [
          "ECDH-ES+A256KW",
          "ECDH-ES+A192KW",
          "ECDH-ES+A128KW",
          "RSA-OAEP",
          "RSA-OAEP-256",
          "RSA1_5",
          "ECDH-ES"
        ],
        "authorization_encryption_enc_values_supported": [
          "A256GCM",
          "A192GCM",
          "A128GCM",
          "A128CBC-HS256",
          "A192CBC-HS384",
          "A256CBC-HS512"
        ],
        "claims_supported": [
          "aud",
          "sub",
          "iss",
          "auth_time",
          "name",
          "given_name",
          "family_name",
          "preferred_username",
          "email",
          "acr"
        ],
        "claim_types_supported": [
          "normal"
        ],
        "claims_parameter_supported": true,
        "scopes_supported": [
          "openid",
          "organization",
          "acr",
          "address",
          "offline_access",
          "email",
          "profile",
          "microprofile-jwt",
          "web-origins",
          "phone",
          "roles",
          "basic"
        ],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": true,
        "code_challenge_methods_supported": [
          "plain",
          "S256"
        ],
        "tls_client_certificate_bound_access_tokens": true,
        "revocation_endpoint": "http://localhost:{0}/protocol/openid-connect/revoke",
        "revocation_endpoint_auth_methods_supported": [
          "private_key_jwt",
          "client_secret_basic",
          "client_secret_post",
          "tls_client_auth",
          "client_secret_jwt"
        ],
        "revocation_endpoint_auth_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "HS256",
          "HS512",
          "ES256",
          "RS256",
          "HS384",
          "ES512",
          "PS256",
          "PS512",
          "RS512"
        ],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "device_authorization_endpoint": "http://localhost:{0}/protocol/openid-connect/auth/device",
        "backchannel_token_delivery_modes_supported": [
          "poll",
          "ping"
        ],
        "backchannel_authentication_endpoint": "http://localhost:{0}/protocol/openid-connect/ext/ciba/auth",
        "backchannel_authentication_request_signing_alg_values_supported": [
          "PS384",
          "RS384",
          "EdDSA",
          "ES384",
          "ES256",
          "RS256",
          "ES512",
          "PS256",
          "PS512",
          "RS512"
        ],
        "require_pushed_authorization_requests": false,
        "pushed_authorization_request_endpoint": "http://localhost:{0}/protocol/openid-connect/ext/par/request",
        "mtls_endpoint_aliases": '{'
          "token_endpoint": "http://localhost:{0}/protocol/openid-connect/token",
          "revocation_endpoint": "http://localhost:{0}/protocol/openid-connect/revoke",
          "introspection_endpoint": "http://localhost:{0}/protocol/openid-connect/token/introspect",
          "device_authorization_endpoint": "http://localhost:{0}/protocol/openid-connect/auth/device",
          "registration_endpoint": "http://localhost:{0}/clients-registrations/openid-connect",
          "userinfo_endpoint": "http://localhost:{0}/protocol/openid-connect/userinfo",
          "pushed_authorization_request_endpoint": "http://localhost:{0}/protocol/openid-connect/ext/par/request",
          "backchannel_authentication_endpoint": "http://localhost:{0}/protocol/openid-connect/ext/ciba/auth"
        },
        "authorization_response_iss_parameter_supported": true
      }
      """;

  static {
    try {
      byte[] keyBytes = new byte[32];
      new SecureRandom().nextBytes(keyBytes);

      RSAKey rsaKey = new RSAKeyGenerator(2048)
          .keyUse(KeyUse.SIGNATURE)
          .algorithm(new Algorithm("RS256"))
          .keyID(new String(keyBytes))
          .generate();

      PRIVATE_KEY = rsaKey.toPrivateKey();

      String jwkResponse = String.format("{\"keys\": [%s]}", rsaKey.toPublicJWK().toJSONString());
      wireMockServer.stubFor(get("/protocol/openid-connect/certs")
          .willReturn(aResponse()
              .withHeader("Content-Type", "application/json")
              .withBody(jwkResponse)));
      wireMockServer.stubFor(get("/.well-known/openid-configuration")
          .willReturn(aResponse()
              .withHeader("Content-Type", "application/json")
              .withBody(MessageFormat.format(ISSUER_CONFIG, String.valueOf(PORT)))));
      wireMockServer.start();

    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }


  public static String getRealmUrl() {
    return "http://localhost:" + PORT;
  }

  static String getAccessToken(String subject, List<String> groups) throws JOSEException {
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(getRealmUrl())
        .subject(subject)
        .claim("iat", System.currentTimeMillis() / 1000)
        .claim("typ", "Bearer")
        .claim("groups", groups)
        .build();

    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(JOSEObjectType.JWT)
            .build(),
        claims
    );

    jwt.sign(new RSASSASigner(PRIVATE_KEY));
    String accessToken = jwt.serialize();
    return accessToken;
  }
}
