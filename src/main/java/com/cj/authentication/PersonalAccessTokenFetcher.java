package com.cj.authentication;

import java.util.Optional;

public interface PersonalAccessTokenFetcher {
    Optional<String> getPersonalAccessToken(String tokenString);
}
