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
    public Optional<String> getPersonalAccessToken(String tokenString) {
        Optional<JSONObject> json = urlToJson(authorizationServiceUrl, tokenString);

        if(json.isPresent())
            return Optional.of(json.get().getString("userId"));
        else
            return Optional.empty();
    }

    public static Optional<JSONObject> urlToJson(URL url, String tokenString) {
        HttpGet httpget = new HttpGet(url.toString());
        httpget.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + tokenString);
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            ResponseHandler<Optional<JSONObject>> responseHandler = response -> {
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    HttpEntity entity = response.getEntity();
                    String jsonString =  entity != null ? EntityUtils.toString(entity) : null;

                    return Optional.of(new JSONObject(jsonString));
                } else {
                    return Optional.empty();
                }
            };
            return httpClient.execute(httpget, responseHandler);
        } catch (IOException e) {
            return Optional.empty();
        }
    }
}
