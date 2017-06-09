package com.cj.authentication;

import com.nimbusds.jose.jwk.JWKSet;

public class StaticTokenVerifier extends AbstractTokenVerifier {
  private final JWKSet publicKeys;

  public StaticTokenVerifier(JWKSet publicKeys) {
    this.publicKeys = publicKeys;
  }

  @Override
  protected JWKSet getPublicKeys() {
    return publicKeys;
  }
}
