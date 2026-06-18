package org.qlein.oidcproxy;

interface BackendInitializer {

  void initialize(BackendConfig backendConfig) throws Exception;
}
