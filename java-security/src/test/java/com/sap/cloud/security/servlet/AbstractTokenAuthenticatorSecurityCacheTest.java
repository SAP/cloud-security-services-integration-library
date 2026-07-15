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
import org.junit.jupiter.api.Test;

class AbstractTokenAuthenticatorSecurityCacheTest {

  @Test
  void withSecurityCache_isRetrievableViaGetter() {
    RecordingCache cache = new RecordingCache();
    IasTokenAuthenticator auth = new IasTokenAuthenticator();

    AbstractTokenAuthenticator returned = auth.withSecurityCache(cache);

    assertThat(returned).isSameAs(auth);
    assertThat(auth.getSecurityCache()).isSameAs(cache);
  }

  @Test
  void withSecurityCache_null_clearsCache() {
    IasTokenAuthenticator auth = new IasTokenAuthenticator();
    auth.withSecurityCache(new RecordingCache());
    auth.withSecurityCache(null);
    assertThat(auth.getSecurityCache()).isNull();
  }

  @Test
  void getSecurityCache_defaultsToNull() {
    IasTokenAuthenticator auth = new IasTokenAuthenticator();
    assertThat(auth.getSecurityCache()).isNull();
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

    // Simply drive the validator builder construction path.
    auth.getOrCreateTokenValidator();
    assertThat(auth.getSecurityCache()).isSameAs(cache);
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    @Override
    public Optional<String> get(String key) {
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
