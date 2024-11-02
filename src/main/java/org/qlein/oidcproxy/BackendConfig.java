package org.qlein.oidcproxy;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.vertx.httpproxy.HttpProxy;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class BackendConfig {

  private String realmUrl;
  private String headerPrefix;
  private String pathPrefix;
  private String backendHost;
  private int backendPort;
  private Map<String, String> headerFilter;
  private List<ClaimFilter> claimFilter;

  @JsonIgnore
  private String backendId;
  @JsonIgnore
  private HttpProxy proxy;
  @JsonIgnore
  private DefaultJWTProcessor<SecurityContext> jwtProcessor;
  @JsonIgnore
  private String configMapField;

  public String getRealmUrl() {
    return realmUrl;
  }

  public BackendConfig setRealmUrl(String realmUrl) {
    this.realmUrl = realmUrl;
    return this;
  }

  public String getBackendId() {
    return backendId;
  }

  public BackendConfig setBackendId(String backendId) {
    this.backendId = backendId;
    return this;
  }

  public String getPathPrefix() {
    return pathPrefix;
  }

  public BackendConfig setPathPrefix(String pathPrefix) {
    this.pathPrefix = pathPrefix;
    return this;
  }

  public String getBackendHost() {
    return backendHost;
  }

  public BackendConfig setBackendHost(String backendHost) {
    this.backendHost = backendHost;
    return this;
  }

  public int getBackendPort() {
    return backendPort;
  }

  public BackendConfig setBackendPort(int backendPort) {
    this.backendPort = backendPort;
    return this;
  }

  public Map<String, String> getHeaderFilter() {
    return headerFilter;
  }

  public BackendConfig setHeaderFilter(
      Map<String, String> headerFilter) {
    this.headerFilter = headerFilter;
    return this;
  }

  public List<ClaimFilter> getClaimFilter() {
    return claimFilter;
  }

  public BackendConfig setClaimFilter(List<ClaimFilter> claimFilter) {
    this.claimFilter = claimFilter;
    return this;
  }

  public HttpProxy getProxy() {
    return proxy;
  }

  public BackendConfig setProxy(HttpProxy proxy) {
    this.proxy = proxy;
    return this;
  }

  public DefaultJWTProcessor<SecurityContext> getJwtProcessor() {
    return jwtProcessor;
  }

  public BackendConfig setJwtProcessor(
      DefaultJWTProcessor<SecurityContext> jwtProcessor) {
    this.jwtProcessor = jwtProcessor;
    return this;
  }

  public BackendConfig setConfigMapField(String configMapField) {
    this.configMapField = configMapField;
    return this;
  }

  public String getConfigMapField() {
    return configMapField;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    BackendConfig that = (BackendConfig) o;
    return Objects.equals(backendId, that.backendId) && Objects.equals(
        configMapField, that.configMapField);
  }

  @Override
  public int hashCode() {
    return Objects.hash(backendId, configMapField);
  }

  public boolean sameRealmAndBackend(BackendConfig backendConfig) {
    return realmUrl.equals(backendConfig.getRealmUrl()) &&
        this.backendHost.equals(backendConfig.getBackendHost()) &&
        this.backendPort == backendConfig.getBackendPort();
  }

  public String getHeaderPrefix() {
    return headerPrefix;
  }

  public BackendConfig setHeaderPrefix(String headerPrefix) {
    this.headerPrefix = headerPrefix;
    return this;
  }
}
