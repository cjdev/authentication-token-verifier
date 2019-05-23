package com.cj.authentication;

import java.io.IOException;
import java.util.Optional;

public interface PersonalAccessTokenFetcher {
    Optional<String> getPersonalAccessToken(String tokenString) throws IOException;
}
