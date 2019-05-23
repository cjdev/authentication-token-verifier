package com.cj.authentication;

import java.text.ParseException;
import java.time.Clock;
import java.util.Optional;

public interface TokenVerifierInterface {
	void init();
	Optional<Token> verifyTokenString(String tokenString);
    Optional<Token> verifyJWTWithClock(String tokenString, Clock clock) throws ParseException;
	Optional<Token> verifyPersonalAccessToken(String tokenString);
}
