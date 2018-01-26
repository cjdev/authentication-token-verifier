package com.cj.authentication;

import java.util.Optional;

public final class Token {
  public final Optional<String> appId;
  public final Optional<String> userId;

  public Token(Optional<String> appId, Optional<String> userId) {
    this.appId = appId;
    this.userId = userId;
  }

  @Override
  public String toString() {
    return "Token{" +
            "appId='" + appId + '\'' +
            ", userId=" + userId +
            '}';
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Token token = (Token) o;

    if (appId != null ? !appId.equals(token.appId) : token.appId != null) return false;
    return userId != null ? userId.equals(token.userId) : token.userId == null;

  }

  @Override
  public int hashCode() {
    int result = appId != null ? appId.hashCode() : 0;
    result = 31 * result + (userId != null ? userId.hashCode() : 0);
    return result;
  }
}
