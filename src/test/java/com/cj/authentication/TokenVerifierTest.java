package com.cj.authentication;

import static org.junit.Assert.*;

import io.jsonwebtoken.Clock;
import io.jsonwebtoken.impl.FixedClock;
import org.junit.Test;

import java.util.Date;
import java.util.Optional;

public class TokenVerifierTest {
  private final Clock beginningClock = new FixedClock(new Date(0L));
  private final Clock endClock = new FixedClock(new Date(Long.MAX_VALUE));

  @Test
  public void verifiesValidTokensWithoutUsers() {
    String str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODM2NDUyMDYsImFwcElkIjoiMTIzNCJ9.6kFuNv0hyTdyWiJ7HYdGls40yYKx5J2WyLPrCpHT8OA";
    Optional<Token> tok = TokenVerifier.verifyTokenStringWithClock("secret", str, beginningClock);
    assertEquals(Optional.of(new Token("1234", Optional.empty())), tok);
  }

  @Test
  public void verifiesValidTokensWithUsers() {
    String str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODM2NDYyNjYsInVzZXJJZCI6IjdhNDFlMWNmLWI5NTItNDUxMy1hMzc4LWFhYzY2YjU5YWEzMyIsImFwcElkIjoiMTIzNCJ9.Pn4m0G-wF6m9-GoOouYKFnu_FMszGxr4CmSeHZ5RVx4";
    Optional<Token> tok = TokenVerifier.verifyTokenStringWithClock("secret", str, beginningClock);
    assertEquals(Optional.of(new Token("1234", Optional.of("7a41e1cf-b952-4513-a378-aac66b59aa33"))), tok);
  }

  @Test
  public void rejectsGibberish() {
    Optional<Token> tok = TokenVerifier.verifyTokenStringWithClock("secret", "asdf", beginningClock);
    assertEquals(Optional.empty(), tok);
  }

  @Test
  public void rejectsTokensWithBadSignature() {
    String str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODM2NDUyMDYsImFwcElkIjoiMTIzNCJ9.6kFuNv0hyTdyWiJ7HYdGls40yYKx5J2WyLPrCpHT8OA";
    Optional<Token> tok = TokenVerifier.verifyTokenStringWithClock("foobar", str, beginningClock);
    assertEquals(Optional.empty(), tok);
  }

  @Test
  public void rejectsExpiredTokens() {
    String str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODM2NDUyMDYsImFwcElkIjoiMTIzNCJ9.6kFuNv0hyTdyWiJ7HYdGls40yYKx5J2WyLPrCpHT8OA";
    Optional<Token> tok = TokenVerifier.verifyTokenStringWithClock("secret", str, endClock);
    assertEquals(Optional.empty(), tok);
  }

  @Test
  public void rejectsTokensWithMissingApplicationId() {
    String str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODM2NDYyNjYsInVzZXJJZCI6IjdhNDFlMWNmLWI5NTItNDUxMy1hMzc4LWFhYzY2YjU5YWEzMyJ9.SqbpJYUS4iVEgGqx6h0SbAXTIqvJYbnTDjD_BZzxz5I";
    Optional<Token> tok = TokenVerifier.verifyTokenStringWithClock("secret", str, beginningClock);
    assertEquals(Optional.empty(), tok);
  }
}
