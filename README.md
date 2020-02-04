# authentication-token-verifier

This project provides the `com.cj:authentication-token-verifier` library, which includes support for consuming and verifying CJ OAuth authentication tokens. The library automatically handles periodically refreshing token signing keys in a background thread, so your application does not need to do any work to properly consume authentication tokens.

To use this library, add it to your application’s pom.xml:

```xml
<dependency>
    <groupId>com.cj</groupId>
    <artifactId>authentication-token-verifier</artifactId>
    <version>3.0.0-SNAPSHOT</version>
</dependency>
```

When your application starts up, create an instance of `com.cj.authentication.TokenVerifier`. You must initialize the `TokenVerifier` with a call to `TokenVerifier#init` before verifying tokens. Each instance of `TokenVerifier` will spawn a background thread, so you will likely want to share a single instance between threads of a multi-threaded application. Since `TokenVerifier` implements `AutoCloseable`, it can be created within a try-with-resources block to ensure the background thread is automatically shut down when it goes out of scope:

```java
try (TokenVerifier tokenVerifier = new TokenVerifier(new URL("https://id.api.cj.com/public-keys"))) {
  // ...
}
```

Now you can call `TokenVerifier#verifyTokenString` to verify a token. If the token is valid, it will produce a `Token` object containing the information stored inside the token. Otherwise, if the token is invalid or expired, it will produce an empty `Optional`.

For an example project that uses this library, see [authentication-token-sample-consumer][].

[authentication-token-sample-consumer]: http://github.com/cjdev/authentication-token-sample-consumer

To deploy to Ad Systems' publicly accessible M2 repo in an S3 bucket:
 * set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY values (ask Ad Systems for values)
 * run `mvn deploy -P cj-adsystems-m2`