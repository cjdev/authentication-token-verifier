package com.cj.authentication;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of {@link AbstractTokenVerifier} that automatically fetches public keys from a remote location,
 * using {@code https://io.cj.com/public-keys} as the default location. Creating an instance of {@link TokenVerifier}
 * automatically spawns a background thread that will periodically (hourly) refresh the set of public keys from the
 * remote source. You should construct a {@link TokenVerifier} in a try-with-resources block to ensure that the
 * background thread is automatically shut down when the instance goes out of scope.
 */
public final class TokenVerifier extends AbstractTokenVerifier implements AutoCloseable {
  private static final long REFRESH_INTERVAL = 60L * 60L * 1000L; // 1 hour in ms
  private static final URL CJ_IO_URL_PUBLIC_KEYS;
  private static final URL TOKEN_VERIFY_URL;

  static {
    try {
      CJ_IO_URL_PUBLIC_KEYS = new URL("https://id.api.cj.com/public-keys");
      TOKEN_VERIFY_URL = new URL("https://id.api.cj.com/token/verify");
    } catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }
  }

  private volatile AtomicBoolean isInitialized = new AtomicBoolean(false);
  private final URL keySetUrl;
  private final Object refreshKeysMonitor = new Object();
  private volatile boolean refreshShouldStop = false;
  private volatile AtomicInteger numSuccessiveRefreshFailures = new AtomicInteger(0);
  private volatile Throwable uncaughtRefreshException;
  private volatile Exception lastRefreshException;

  private volatile JWKSet keySet;

  private volatile Thread refreshKeysThread;

  /**
   * Creates a token verifier that fetches keys from the provided URL.
   *
   * @param keySetUrl full HTTP URL to fetch keys from
   */
  public TokenVerifier(URL keySetUrl, PersonalAccessTokenFetcher personalAccessTokenFetcher) {
    super(personalAccessTokenFetcher);
    this.keySetUrl = keySetUrl;
  }

  public TokenVerifier(URL keySetUrl, URL tokenVerifyUrl) {
    this(keySetUrl, new PersonalAccessTokenReal(tokenVerifyUrl));
  }

  /**
   * Creates a token verifier that fetches keys from the default location, {@code https://id.api.cj.com/public-keys}.
   */
  public TokenVerifier(URL keySetUrl) {
    this(keySetUrl, new PersonalAccessTokenReal(TOKEN_VERIFY_URL));
  }

  public TokenVerifier(){
    this(CJ_IO_URL_PUBLIC_KEYS, new PersonalAccessTokenReal(TOKEN_VERIFY_URL));
  }

  private synchronized void fetchPublicKeys() throws IOException, ParseException {
    int connectTimeout = 5000;
    int readTimeout = 5000;
    int infiniteSize = 0;
    keySet = JWKSet.load(keySetUrl, connectTimeout, readTimeout, infiniteSize);
  }

  @Override
  protected JWKSet getPublicKeys() {
    // if init() fails, keySet will still be null, so try again
    if (keySet == null) {
        try {
          fetchPublicKeys();
        } catch (Exception e) {
          throw new RuntimeException("Error when fetching public keys", e);
        }
    }
    return keySet;
  }

  private void startRefreshThread() {
    if (refreshKeysThread == null) {
      refreshKeysThread = new Thread(() -> {
        synchronized (refreshKeysMonitor) {
          while (!refreshShouldStop) {
            try {
              refreshKeysMonitor.wait(REFRESH_INTERVAL);
            } catch (InterruptedException e) {
              continue;
            }
            try {
              fetchPublicKeys();
              numSuccessiveRefreshFailures.set(0);
            } catch (Exception e) {
              lastRefreshException = e;
              numSuccessiveRefreshFailures.incrementAndGet();
            }
          }
        }
      });
      refreshKeysThread.setDaemon(true);
      refreshKeysThread.setUncaughtExceptionHandler((t, e) -> uncaughtRefreshException = e);
      refreshKeysThread.start();
    }
  }

  /**
   * Initializes the TokenVerifier and spawns a background thread to refresh public keys. After the first call to this
   * method, subsequent calls will have no effect.
   */
  public void init() {
    if (!isInitialized.getAndSet(true)) {
      startRefreshThread();
      try {
        fetchPublicKeys();
      } catch (Exception e) {
        isInitialized.set(false);
        throw new RuntimeException("init() failed, error when fetching public keys", e);
      }
    }
  }

  @Override
  protected Optional<Token> verifySignedJWTWithClock(SignedJWT signedJWT, JWTClaimsSet jwtClaimsSet, Clock clock) {
    if (uncaughtRefreshException != null) {
      throw new RuntimeException("Uncaught internal error when fetching public keys", uncaughtRefreshException);
    }
    if (numSuccessiveRefreshFailures.get() >= 5) {
      throw new RuntimeException("Too many successive failures fetching public keys", lastRefreshException);
    }
    return super.verifySignedJWTWithClock(signedJWT, jwtClaimsSet, clock);
  }

  @Override
  protected void finalize() throws Throwable {
    this.close();
    super.finalize();
  }

  @Override
  public void close() {
    synchronized (refreshKeysMonitor) {
      refreshShouldStop = true;
      refreshKeysMonitor.notifyAll();
    }
  }
}
