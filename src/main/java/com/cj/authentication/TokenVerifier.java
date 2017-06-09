package com.cj.authentication;

import com.nimbusds.jose.jwk.JWKSet;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Clock;
import java.util.Optional;
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
  private static final URL CJ_IO_URL;

  static {
    try {
      CJ_IO_URL = new URL("https://io.cj.com/public-keys");
    } catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }
  }

  private final URL keySetUrl;
  private final Object refreshKeysMonitor = new Object();
  private volatile boolean refreshShouldStop = false;
  private volatile AtomicInteger numSuccessiveRefreshFailures = new AtomicInteger(0);
  private volatile Throwable uncaughtRefreshException;
  private volatile Exception lastRefreshException;

  private volatile JWKSet keySet;

  /**
   * Creates a token verifier that fetches keys from the provided URL.
   *
   * @param keySetUrl full HTTP URL to fetch keys from
   */
  public TokenVerifier(URL keySetUrl) {
    this.keySetUrl = keySetUrl;

    try {
      this.keySet = fetchPublicKeys();
    } catch (IOException | ParseException e) {
      throw new RuntimeException("Error when performing initial fetch of public keys", e);
    }

    Thread refreshKeysThread = new Thread(() -> {
      synchronized (refreshKeysMonitor) {
        while (!refreshShouldStop) {
          try {
            refreshKeysMonitor.wait(REFRESH_INTERVAL);
          } catch (InterruptedException e) {
            continue;
          }
          try {
            keySet = fetchPublicKeys();
          } catch (IOException | ParseException e) {
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

  /**
   * Creates a token verifier that fetches keys from the default location, {@code https://io.cj.com/public-keys}.
   */
  public TokenVerifier() {
    this(CJ_IO_URL);
  }

  private JWKSet fetchPublicKeys() throws IOException, ParseException {
    return JWKSet.load(keySetUrl);
  }

  @Override
  protected JWKSet getPublicKeys() {
    return keySet;
  }

  @Override
  public Optional<Token> verifyTokenStringWithClock(String tokenString, Clock clock) {
    if (uncaughtRefreshException != null) {
      throw new RuntimeException("Uncaught internal error when fetching public keys", uncaughtRefreshException);
    }
    if (numSuccessiveRefreshFailures.get() >= 5) {
      throw new RuntimeException("Too many successive failures fetching public keys", lastRefreshException);
    }
    return super.verifyTokenStringWithClock(tokenString, clock);
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
