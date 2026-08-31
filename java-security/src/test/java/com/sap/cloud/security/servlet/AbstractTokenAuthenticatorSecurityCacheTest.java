/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import static org.assertj.core.api.Assertions.assertThat;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AbstractTokenAuthenticatorSecurityCacheTest {

  @Test
  void withSecurityCache_returnsSameAuthenticator() {
    RecordingCache cache = new RecordingCache();
    IasTokenAuthenticator auth = new IasTokenAuthenticator();
    AbstractTokenAuthenticator returned = auth.withSecurityCache(cache);
    assertThat(returned).isSameAs(auth);
  }

  @Test
  void withSecurityCache_isPassedIntoValidatorBuilder() {
    RecordingCache cache = new RecordingCache();

    OAuth2ServiceConfiguration cfg =
        OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
            .withDomains("myauth.com")
            .withClientId("cid-" + System.nanoTime())
            .build();

    IasTokenAuthenticator auth =
        (IasTokenAuthenticator)
            new IasTokenAuthenticator().withServiceConfiguration(cfg).withSecurityCache(cache);

    auth.getOrCreateTokenValidator();

    // The cache must not have been touched during validator construction — it is wired in
    // passively and only consulted on actual JWKS / OIDC fetches.
    assertThat(cache.getCallCount.get()).isEqualTo(0);
  }

  @Test
  void withSecurityCache_null_resetsToDefault() {
    IasTokenAuthenticator auth = new IasTokenAuthenticator();
    auth.withSecurityCache(new RecordingCache());
    // Passing null must not throw and must restore the default (no external cache).
    auth.withSecurityCache(null);
    assertThat(auth.getSecurityCache()).isNull();
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    final AtomicInteger getCallCount = new AtomicInteger();

    @Override
    public Optional<String> get(String key) {
      getCallCount.incrementAndGet();
      return Optional.empty();
    }

    @Override
    public void set(String key, String value, Duration ttl) {}

    @Override
    public void delete(String key) {}

    @Override
    public void clear() {}
  }
}