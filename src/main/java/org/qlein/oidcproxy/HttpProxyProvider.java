package org.qlein.oidcproxy;

import io.netty.util.internal.StringUtil;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;

public class HttpProxyProvider {

  private static Proxy _proxy;

  static {
    String proxyStr = System.getProperty(
        "http_proxy",
        null
    );
    if (!StringUtil.isNullOrEmpty(proxyStr)) {
      String[] proxyParts = proxyStr.split(":");
      _proxy = new Proxy(
          Type.HTTP,
          InetSocketAddress.createUnresolved(
              proxyParts[0],
              Integer.parseInt(proxyParts[1])
          )
      );
    }
  }

  public static boolean isHttpProxyConfigured() {
    return _proxy != null;
  }

  public static Proxy getHttpProxy() {
    return _proxy;
  }
}
