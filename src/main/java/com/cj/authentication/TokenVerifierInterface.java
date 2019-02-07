package com.cj.authentication;

import java.time.Clock;
import java.util.Optional;

public interface TokenVerifierInterface {
	Optional<Token> verifyTokenString(String tokenString);
	Optional<Token> verifyTokenStringWithClock(String tokenString, Clock clock);
	Optional<Token> verifyPersonalAccessToken(String tokenString);
}
