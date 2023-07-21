/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.github.benmanes.caffeine.cache.Ticker;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OAuth2TokenKeyServiceWithCacheTest {

	public static final TokenKeyCacheConfiguration CACHE_CONFIGURATION = TokenKeyCacheConfiguration
			.defaultConfiguration();

	OAuth2TokenKeyServiceWithCache cut;
	OAuth2TokenKeyService tokenKeyServiceMock;
	URI TOKEN_KEYS_URI = URI.create("https://myauth.com/jwks_uri");
	private static final String APP_TID = "app_tid";
	private TestCacheTicker testCacheTicker;
	private static final String CLIENT_ID = "client_id";

	@Before
	public void setup() throws IOException {
		tokenKeyServiceMock = mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(eq(TOKEN_KEYS_URI), isNotNull(), any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		testCacheTicker = new TestCacheTicker();
		cut = createCut(CACHE_CONFIGURATION);
	}

	@Test
	public void getFreshInstance() {
		assertThat(cut).isNotSameAs(OAuth2TokenKeyServiceWithCache.getInstance());
	}

	@Test
	public void changeCacheConfiguration() {
		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofSeconds(678), 1234, false));

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(1234);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(Duration.ofSeconds(678));
	}

	@Test
	public void changeCacheConfiguration_valuesTooLow_leftUnchanged() {
		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();
		int oldCacheSize = cut.getCacheConfiguration().getCacheSize();

		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofSeconds(1), 1, false));

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(oldCacheSize);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void changeCacheConfiguration_tooLongDuration_leftUnchanged() {
		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();

		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofMinutes(16), 601, false));

		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void retrieveTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key1 = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		PublicKey key2 = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, "other-zone-id", CLIENT_ID);

		assertThat(String.valueOf(key1.getAlgorithm())).isEqualTo("RSA");
		assertThat(String.valueOf(key2.getAlgorithm())).isEqualTo("RSA");
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(TOKEN_KEYS_URI, "other-zone-id", CLIENT_ID);
	}

	@Test
	public void getCachedTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);

		assertThat(cachedKey).isNotNull().isSameAs(key);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), any(), eq(CLIENT_ID));
	}

	@Test
	public void retrieveNoTokenKeys_returnsNull()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.withTokenKeyService(mock(OAuth2TokenKeyService.class));
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID);

		assertThat(key).isNull();
	}

	@Test
	public void requestFails_throwsException() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), any(), any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));

		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Currently unavailable");
	}

	@Test
	public void retrieveTokenKeys_afterCacheWasCleared()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID);
		cut.clearCache();
		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID);

		assertThat(cachedKey).isNotNull();
		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(APP_TID), any());
	}

	@Test
	public void getCachedTokenKeys_noZoneId() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		when(tokenKeyServiceMock.retrieveTokenKeys(eq(TOKEN_KEYS_URI), isNull(), eq(CLIENT_ID)))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, null, CLIENT_ID);
		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, null, CLIENT_ID);

		assertThat(cachedKey).isNotNull().isSameAs(key);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), isNull(), eq(CLIENT_ID));
	}

	@Test
	public void retrieveTokenKeys_doesRequestKeysAgainAfterCacheExpired()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		testCacheTicker.advance(CACHE_CONFIGURATION.getCacheDuration()); // just expired
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(APP_TID), eq(CLIENT_ID));
	}

	@Test
	public void cacheStatistics_isDisabled_statisticsObjectIsNull() {
		cut = createCut(TokenKeyCacheConfiguration
				.getInstance(CACHE_CONFIGURATION.getCacheDuration(), CACHE_CONFIGURATION.getCacheSize(), false));

		assertThat(cut.getCacheStatistics()).isNull();
	}

	@Test
	public void cacheStatistics_isEnabled_returnsStatisticsObject() {
		cut = createCut(TokenKeyCacheConfiguration
				.getInstance(CACHE_CONFIGURATION.getCacheDuration(), CACHE_CONFIGURATION.getCacheSize(), true));

		assertThat(cut.getCacheStatistics()).isInstanceOf(CacheStats.class);
	}

	@Test
	public void retrieveTokenKeysForNewKeyId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "not-seen-yet", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);

		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(APP_TID), eq(CLIENT_ID));
	}

	@Test
	public void retrieveTokenKeysForNewZoneId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID + "-2", CLIENT_ID);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), any(), any());
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(APP_TID), eq(CLIENT_ID));
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(APP_TID + "-2"), eq(CLIENT_ID));
	}

	@Test
	public void retrieveTokenKeysForAnotherInvalidZoneId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), eq("invalid-tenant"), eq(CLIENT_ID)))
				.thenThrow(new OAuth2ServiceException("Invalid app_tid provided"));
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID);

		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, "invalid-tenant", CLIENT_ID);
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Invalid");
		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, "invalid-tenant", CLIENT_ID);
		}).isInstanceOf(OAuth2ServiceException.class)
				.hasMessageStartingWith("Keys not accepted for app_tid invalid-tenant");

		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq("invalid-tenant"), eq(CLIENT_ID));
	}

	@Test
	public void retrieveTokenKeysForNewEndpoint()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, APP_TID, CLIENT_ID);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", URI.create("http://another/url"), APP_TID, CLIENT_ID);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(APP_TID), eq(CLIENT_ID));
	}

	private OAuth2TokenKeyServiceWithCache createCut(TokenKeyCacheConfiguration cacheConfiguration) {
		return OAuth2TokenKeyServiceWithCache
				.getInstance(testCacheTicker)
				.withTokenKeyService(tokenKeyServiceMock)
				.withCacheConfiguration(cacheConfiguration);
	}

	private class TestCacheTicker implements Ticker {
		long elapsed = 0;

		@Override
		public long read() {
			return elapsed;
		}

		public void advance(Duration duration) {
			this.elapsed = elapsed + duration.toNanos();
		}
	}
}
