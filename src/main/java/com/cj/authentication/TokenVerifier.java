package com.cj.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.DefaultClock;
import java.util.Optional;

public final class TokenVerifier {
  /**
   * Verifies and decodes a JWT representing a bearer token.
   *
   * If a token is properly formatted, correctly signed, and has not expired, then this function
   * will return a decoded {@link Token}. Otherwise, it will return an empty {@link Optional}.
   *
   * @param secret the secret used to sign and verify tokens
   * @param tokenString the signed, base 64 encoded JWT
   * @return a decoded token or nothing
   */
  public static Optional<Token> verifyTokenString(String secret, String tokenString) {
    return verifyTokenStringWithClock(secret, tokenString, DefaultClock.INSTANCE);
  }

  static Optional<Token> verifyTokenStringWithClock(String secret, String tokenString, Clock clock) {
    try {
      Claims claims = Jwts.parser()
              .setClock(clock)
              .setSigningKey(secret.getBytes())
              .parseClaimsJws(tokenString)
              .getBody();

      Object appId = claims.get("appId");
      Object userId = claims.get("userId");
      if (!(appId instanceof String)
              || (userId != null && !(userId instanceof String))) {
        return Optional.empty();
      }

      return Optional.of(new Token((String) appId, Optional.ofNullable((String) userId)));
    } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private TokenVerifier() {}
}
