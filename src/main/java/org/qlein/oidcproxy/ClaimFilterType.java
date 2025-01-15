package org.qlein.oidcproxy;

import java.util.List;
import java.util.function.BiFunction;

public enum ClaimFilterType {
  string_contains((s, s2) -> s.toString().contains(s2)),
  list_contains((list, s2) -> ((List) list).contains(s2)),
  equals(Object::equals);

  private final BiFunction<Object, String, Boolean> filterMatchFunction;

  ClaimFilterType(BiFunction<Object, String, Boolean> filterMatchFunction) {
    this.filterMatchFunction = filterMatchFunction;
  }

  public ClaimFilter get(String key, String value) {
    return new ClaimFilter().setType(this).setKey(key).setValue(value);
  }

  public boolean matches(Object claimValue, String filterValue) {
    return filterMatchFunction.apply(claimValue, filterValue);
  }
}
