package com.cj.authentication;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.Assert.assertEquals;

public class TokenVerifierTest {
  private final Clock beginningClock = Clock.fixed(Instant.MIN, ZoneOffset.UTC);
  private final Clock endClock = Clock.fixed(Instant.MAX, ZoneOffset.UTC);

  private final AbstractTokenVerifier tokenVerifier;

  public TokenVerifierTest() {
    try {
      File keypairFile = new File(getClass().getClassLoader().getResource("rsa-keypairs-jwkset.json").getFile());
      tokenVerifier = new StaticTokenVerifier(JWKSet.load(keypairFile).toPublicJWKSet());
    } catch (IOException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void verifiesValidTokensWithoutUsers() {
    String str = "eyJhbGciOiJQUzUxMiJ9.eyJleHAiOjEuNDk3MTM1NTIyMTc0MzY2ZTksImFwcElkIjoiMTIzNCIsImF1ZCI6ImNqIn0.RktG5sUkz8liMNGVsL67FR5amOZVB7dJofGZzuqtLUow-HuXF63fXI1x8fCcxUC0KSwnzuNQc_11MLiltMIdDsfLt7p0g8HTPCe5EXPtgXIMa8kvIzI3-EiE2FVZClCoyOlhJHyv_jEM-C7NpvqfMJDwwQeouvRhBeurYyMR2Wh_9De1PaQd8ujLTOotPoL467og_mH_lgGwKhuzaSJxxNDJCuWaoJJOmhJec8WQP4xPnfT0oH_uPZd4LEIMq6vkIWHGmXsseQ2_JWaaMzU3MmWA58weMZLLVxmKqdaRjE1TZf1Q0xU5ZEBuP2z487j7cUPt8YNrJWP-0u5XHA7p5g";
    Optional<Token> tok = tokenVerifier.verifyTokenStringWithClock(str, beginningClock);
    assertEquals(Optional.of(new Token("1234", Optional.empty())), tok);
  }

  @Test
  public void verifiesValidTokensWithUsers() {
    String str = "eyJhbGciOiJQUzUxMiJ9.eyJleHAiOjEuNDk3MTM3NjMzMTQ1MTcyZTksInVzZXJJZCI6IjdhNDFlMWNmLWI5NTItNDUxMy1hMzc4LWFhYzY2YjU5YWEzMyIsImFwcElkIjoiMTIzNCIsImF1ZCI6ImNqIn0.gbseT7DabHcnGL2QmlHRuyQtkOhRYZ1DfAqpUkSp8sYqClqbF0UpG56HL9PoP3gReZ3SVVWoFmyYqbYNzgubs0v-cqIgzSYfuON_HIYyBf5H51RHa4397ad8kvc3r6RFQccOO-AeltxVEATjUMa6R2LwlxPjmFMZNZf8VU4wG95QtJ9boeHEd7vFil_u7Joboaw9wkeBC4GOWL_TWlMrGNVYghqcYpxS-QsGOH76EqeVjIfP39c_C-QMvYeOChmoIIbT6REcTul6FIVVAyBcBPB6f_nbDKsvFeO3MTvtTaDc4UKbrdcPQAGBPc2JRarKflo5aB2SwlaOyDGZ_Q6GHw";
    Optional<Token> tok = tokenVerifier.verifyTokenStringWithClock(str, beginningClock);
    assertEquals(Optional.of(new Token("1234", Optional.of("7a41e1cf-b952-4513-a378-aac66b59aa33"))), tok);
  }

  @Test
  public void rejectsGibberish() {
    Optional<Token> tok = tokenVerifier.verifyTokenStringWithClock("asdf", beginningClock);
    assertEquals(Optional.empty(), tok);
  }

  @Test
  public void rejectsTokensWithBadSignature() {
    String str = "eyJhbGciOiJQUzUxMiJ9.eyJleHAiOjEuNDk3MTM1NTIyMTc0MzY2ZTksImFwcElkIjoiMTIzNCIsImF1ZCI6ImNqIn0.bad";
    Optional<Token> tok = tokenVerifier.verifyTokenStringWithClock(str, beginningClock);
    assertEquals(Optional.empty(), tok);
  }

  @Test
  public void rejectsExpiredTokens() {
    String str = "eyJhbGciOiJQUzUxMiJ9.eyJleHAiOjEuNDk3MTM1NTIyMTc0MzY2ZTksImFwcElkIjoiMTIzNCIsImF1ZCI6ImNqIn0.RktG5sUkz8liMNGVsL67FR5amOZVB7dJofGZzuqtLUow-HuXF63fXI1x8fCcxUC0KSwnzuNQc_11MLiltMIdDsfLt7p0g8HTPCe5EXPtgXIMa8kvIzI3-EiE2FVZClCoyOlhJHyv_jEM-C7NpvqfMJDwwQeouvRhBeurYyMR2Wh_9De1PaQd8ujLTOotPoL467og_mH_lgGwKhuzaSJxxNDJCuWaoJJOmhJec8WQP4xPnfT0oH_uPZd4LEIMq6vkIWHGmXsseQ2_JWaaMzU3MmWA58weMZLLVxmKqdaRjE1TZf1Q0xU5ZEBuP2z487j7cUPt8YNrJWP-0u5XHA7p5g";
    Optional<Token> tok = tokenVerifier.verifyTokenStringWithClock(str, endClock);
    assertEquals(Optional.empty(), tok);
  }

  @Test
  public void rejectsTokensWithMissingApplicationId() {
    String str = "eyJhbGciOiJQUzUxMiJ9.eyJleHAiOjEuNDk3MDQyOTk3MTE1NjEyZTksImF1ZCI6ImNqIn0.McHBAfgjGy5INEDwdh4a2DugitWsuk1pi7CbFLE5bB-T0qCwnbXHm_zyZmwDgzlGqCZRGFQ7-c9Qqpjn-bUvVDL2ShHMRcslNcd2LV8wgoJNs1NVbBpnjWDkhWyF7L1SZQWeHjUgPCCPS3ba7DRzuA0dEHLlcr_rZRD1IsDEIyyn88pTbYS5cd98OyXkfhWSMZQJ0DYLAcwjkpqXltB5-tAwPgyUTCXvul4DZYigVIef0TIKwdDofDtC1JCXNR05mbAVlUiZcW8LgRNMs-Xvzc6tJ1sBPqCTw0WsSttYQyCxSGxtLYSmqPOyslZ8VManHJOTW45qhMuC49n1Zmbq4g";
    Optional<Token> tok = tokenVerifier.verifyTokenStringWithClock(str, beginningClock);
    assertEquals(Optional.empty(), tok);
  }
}
