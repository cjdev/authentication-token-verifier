package com.cj.authentication;

import java.util.Optional;

public class StaticPersonalAccessTokenFetcher implements PersonalAccessTokenFetcher {
    @Override
    public Optional<String> getPersonalAccessToken(String tokenString) {
        if(tokenString == "userId")
            return Optional.of("userId");
        else
            return Optional.empty();
    }
}
