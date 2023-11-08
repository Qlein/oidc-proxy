package org.qlein.oidcproxy;

import java.util.function.BiFunction;

public enum ClaimFilterType {
  contains(String::contains);

  private final BiFunction<String, String, Boolean> filterMatchFunction;

  ClaimFilterType(BiFunction<String, String, Boolean> filterMatchFunction) {
    this.filterMatchFunction = filterMatchFunction;
  }

  public ClaimFilter get(String key, String value) {
    return new ClaimFilter().setType(this).setKey(key).setValue(value);
  }

  public boolean matches(String claimValue, String filterValue) {
    return filterMatchFunction.apply(claimValue, filterValue);
  }
}
