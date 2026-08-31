/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import jakarta.annotation.Nonnull;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OidcConfigurationServiceWithCacheSecurityCacheTest {

  private static final URI DISCOVERY =
      URI.create("https://myauth.com/.well-known/oidc-config");

  private OidcConfigurationService svc;
  private OAuth2ServiceEndpointsProvider provider;

  @BeforeEach
  void setup() throws Exception {
    provider = mock(OAuth2ServiceEndpointsProvider.class);
    when(provider.getTokenEndpoint()).thenReturn(URI.create("https://myauth.com/oauth/token"));
    when(provider.getAuthorizeEndpoint())
        .thenReturn(URI.create("https://myauth.com/oauth/authorize"));
    when(provider.getJwksUri()).thenReturn(URI.create("https://myauth.com/jwks"));
    svc = mock(OidcConfigurationService.class);
    when(svc.retrieveEndpoints(any())).thenReturn(provider);
  }

  @Test
  void cacheHit_reconstructsUris() throws Exception {
    RecordingCache cache = new RecordingCache();
    OidcConfigurationServiceWithCache cut =
        OidcConfigurationServiceWithCache.getInstance()
            .withOidcConfigurationService(svc)
            .withSecurityCache(cache);

    OAuth2ServiceEndpointsProvider first = cut.getOrRetrieveEndpoints(DISCOVERY);
    OAuth2ServiceEndpointsProvider second = cut.getOrRetrieveEndpoints(DISCOVERY);

    verify(svc, times(1)).retrieveEndpoints(DISCOVERY);
    assertThat(cache.setCount.get()).isEqualTo(1);
    assertThat(cache.getCount.get()).isEqualTo(2);
    assertThat(second.getTokenEndpoint()).isEqualTo(first.getTokenEndpoint());
    assertThat(second.getAuthorizeEndpoint()).isEqualTo(first.getAuthorizeEndpoint());
    assertThat(second.getJwksUri()).isEqualTo(first.getJwksUri());
  }

  @Test
  void cacheErrors_areSwallowed() throws Exception {
    OidcConfigurationServiceWithCache cut =
        OidcConfigurationServiceWithCache.getInstance()
            .withOidcConfigurationService(svc)
            .withSecurityCache(new ThrowingCache());
    assertThatCode(
            () -> {
              cut.getOrRetrieveEndpoints(DISCOVERY);
              cut.getOrRetrieveEndpoints(DISCOVERY);
            })
        .doesNotThrowAnyException();
    // Cache is broken, so every call refetches.
    verify(svc, times(2)).retrieveEndpoints(DISCOVERY);
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    final AtomicInteger getCount = new AtomicInteger();
    final AtomicInteger setCount = new AtomicInteger();
    private final Map<String, String> store = new HashMap<>();

    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      getCount.incrementAndGet();
      return Optional.ofNullable(store.get(key));
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      setCount.incrementAndGet();
      store.put(key, value);
    }

    @Override
    public void delete(@Nonnull String key) {
      store.remove(key);
    }

    @Override
    public void clear() {
      store.clear();
    }
  }

  private static class ThrowingCache implements SecurityCache<String, String> {
    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      throw new RuntimeException("boom");
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      throw new RuntimeException("boom");
    }

    @Override
    public void delete(@Nonnull String key) {
      throw new RuntimeException("boom");
    }

    @Override
    public void clear() {
      throw new RuntimeException("boom");
    }
  }
}
