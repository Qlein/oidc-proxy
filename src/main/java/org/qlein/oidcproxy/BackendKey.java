package org.qlein.oidcproxy;

record BackendKey(String backendId, String configMapField) {

  static BackendKey from(BackendConfig backendConfig) {
    return new BackendKey(backendConfig.getBackendId(), backendConfig.getConfigMapField());
  }
}
