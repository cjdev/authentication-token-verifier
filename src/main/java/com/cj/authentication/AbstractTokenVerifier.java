package com.cj.authentication;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.text.ParseException;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * An abstract class that implements verification of an RSA-signed JWT string encoded with the compact encoding. For an
 * implementation of this class that automatically fetches the CJ-provided public keys (and periodically updates them in
 * the background), see {@link TokenVerifier}.
 */
public abstract class AbstractTokenVerifier implements TokenVerifierInterface {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private final PersonalAccessTokenFetcher personalAccessTokenFetcher;

  public AbstractTokenVerifier(PersonalAccessTokenFetcher personalAccessTokenFetcher){
    this.personalAccessTokenFetcher = personalAccessTokenFetcher;
  }

  protected abstract JWKSet getPublicKeys();

  private List<RSAKey> getRSAKeys() {
    return getPublicKeys().getKeys().stream()
            .filter(RSAKey.class::isInstance)
            .map(RSAKey.class::cast)
            .collect(Collectors.toList());
  }

  public abstract void init();

  /**
   * Verifies and decodes a JWT representing a bearer token.
   *
   * If a token is properly formatted, correctly signed, and has not expired, then this function
   * will return a decoded {@link Token}. Otherwise, it will return an empty {@link Optional}.
   *
   * @param tokenString the signed, base 64 encoded JWT
   * @return a decoded token or nothing
   */
  public Optional<Token> verifyTokenString(String tokenString) {
    try {
      return verifyJWTWithClock(tokenString, Clock.systemUTC());
    } catch (ParseException e) {
      return verifyPersonalAccessToken(tokenString);
    }
  }

  public Optional<Token> verifyJWTWithClock(String tokenString, Clock clock) throws ParseException {
    SignedJWT signedJWT = SignedJWT.parse(tokenString);
    JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
    return verifySignedJWTWithClock(signedJWT, jwtClaimsSet, clock);
  }

  public Optional<Token> verifyPersonalAccessToken(String tokenString) {
    Optional<String> userId = personalAccessTokenFetcher.getPersonalAccessToken(tokenString);
    if(userId.isPresent())
      return Optional.of(new Token(Optional.empty(), userId));
    else
      return Optional.empty();
  }

  protected Optional<Token> verifySignedJWTWithClock(SignedJWT signedJWT, JWTClaimsSet jwtClaimsSet, Clock clock) {
    for (RSAKey key : getRSAKeys()) {
      try {
        JWSVerifier verifier = new RSASSAVerifier(key);
         try {
           if (!signedJWT.verify(verifier)) continue;
           Optional<Token> maybeToken = verifyClaimsSet(jwtClaimsSet, clock);
           if (maybeToken.isPresent()) return maybeToken;
         } catch (JOSEException e) {}
      } catch (JOSEException e) {
        throw new RuntimeException("Error when verifying token", e);
      }
    }
      return Optional.empty();
  }

  private Optional<Token> verifyClaimsSet(JWTClaimsSet claims, Clock clock) {
    if (clock.instant().isAfter(claims.getExpirationTime().toInstant()))
      return Optional.empty();

    Object appId = claims.getClaims().get("appId");
    Object userId = claims.getClaims().get("userId");
    if (!(appId instanceof String)
            || (userId != null && !(userId instanceof String))) {
      return Optional.empty();
    }

    return Optional.of(new Token((Optional.ofNullable((String) appId)), Optional.ofNullable((String) userId)));
  }
}
