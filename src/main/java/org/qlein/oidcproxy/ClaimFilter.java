package org.qlein.oidcproxy;

public class ClaimFilter {

  private String key;
  private String value;

  private ClaimFilterType type;

  public String getKey() {
    return key;
  }

  public ClaimFilter setKey(String key) {
    this.key = key;
    return this;
  }

  public String getValue() {
    return value;
  }

  public ClaimFilter setValue(String value) {
    this.value = value;
    return this;
  }

  public ClaimFilterType getType() {
    return type;
  }

  public ClaimFilter setType(ClaimFilterType type) {
    this.type = type;
    return this;
  }
}
