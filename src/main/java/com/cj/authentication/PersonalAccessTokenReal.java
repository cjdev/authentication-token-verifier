package com.cj.authentication;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URL;
import java.util.Optional;

public class PersonalAccessTokenReal implements PersonalAccessTokenFetcher {

    private URL authorizationServiceUrl;
    public PersonalAccessTokenReal(URL authorizationServiceUrl) {
        this.authorizationServiceUrl = authorizationServiceUrl;
    }

    @Override
    public Optional<String> getPersonalAccessToken(String tokenString) throws IOException {
        return urlToJson(authorizationServiceUrl, tokenString).map(json -> json.getString("userId"));
    }

    private static Optional<JSONObject> urlToJson(URL url, String tokenString) throws IOException {
        HttpGet httpget = new HttpGet(url.toString());
        httpget.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + tokenString);
        ResponseHandler<Optional<JSONObject>> responseHandler = response -> {
            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    String jsonString = EntityUtils.toString(entity);
                    return Optional.of(new JSONObject(jsonString));
                }
            }
            return Optional.empty();
        };
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            return httpClient.execute(httpget, responseHandler);
        }
    }
}
