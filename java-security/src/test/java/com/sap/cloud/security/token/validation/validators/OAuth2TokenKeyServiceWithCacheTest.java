package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;


public class OAuth2TokenKeyServiceWithCacheTest {
	private static final int CACHE_TIME_IN_SECONDS = 1000;

	OAuth2TokenKeyServiceWithCache cut;
	OAuth2TokenKeyService tokenKeyServiceMock;
	URI TOKEN_KEYS_URI = URI.create("https://myauth.com/jwks_uri");
	private TestCacheTicker testCacheTicker;

	@Before
	public void setup() throws IOException {
		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(TOKEN_KEYS_URI))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		testCacheTicker = new TestCacheTicker();
		cut = OAuth2TokenKeyServiceWithCache
				.getInstance(testCacheTicker)
				.withTokenKeyService(tokenKeyServiceMock)
				.withCacheTime(CACHE_TIME_IN_SECONDS);
	}

	@Test
	public void getFreshInstance() {
		assertThat(cut).isNotSameAs(OAuth2TokenKeyServiceWithCache.getInstance());
	}

	@Test
	public void changeCacheConfiguration() {
		cut = cut.withCacheSize(1001).withCacheTime(601);

		assertThatThrownBy(() -> {
			cut = cut.withCacheSize(1000).withCacheTime(601);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("size");

		assertThatThrownBy(() -> {
			cut = cut.withCacheSize(1001).withCacheTime(600);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("validity");
	}

	@Test
	public void retrieveTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(String.valueOf(key.getAlgorithm())).isEqualTo("RSA");

		Mockito.verify(tokenKeyServiceMock, times(1))
				.retrieveTokenKeys(TOKEN_KEYS_URI);
	}

	@Test
	public void getCachedTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);

		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(cachedKey).isNotNull();
		assertThat(cachedKey).isSameAs(key);

		Mockito.verify(tokenKeyServiceMock, times(1))
				.retrieveTokenKeys(TOKEN_KEYS_URI);
	}

	@Test
	public void retrieveNoTokenKeys_returnsNull()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.withTokenKeyService(Mockito.mock(OAuth2TokenKeyService.class));
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(key).isNull();
	}

	@Test
	public void requestFails_throwsException() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));

		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Currently unavailable");
	}

	@Test
	public void retrieveTokenKeys_afterCacheWasCleared()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);

		cut.clearCache();

		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		assertThat(cachedKey).isNotNull();

		Mockito.verify(tokenKeyServiceMock, times(2))
				.retrieveTokenKeys(TOKEN_KEYS_URI);
	}

	@Test
	public void retrieveTokenKeys_doesNotRequestKeysFromSameUriTwice()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "non-existing-key-id-0", TOKEN_KEYS_URI);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "non-existing-key-id-1", TOKEN_KEYS_URI);

		Mockito.verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any());
	}

	@Test
	public void retrieveTokenKeys_doesRequestKeysFromSameUriAgainAfterCacheExpired()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		testCacheTicker.advance(CACHE_TIME_IN_SECONDS, TimeUnit.SECONDS);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		Mockito.verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any());
	}

	@Test
	public void retrieveTokenKeysFromAnotherEndpoint()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-1", TOKEN_KEYS_URI);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", URI.create("http://another/url"));

		Mockito.verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any());
	}

	@Test
	public void retrieveTokenKeys_cachesAllKeysFromService()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey firstKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);
		PublicKey secondKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-1", TOKEN_KEYS_URI);
		PublicKey thirdKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "legacy-token-key", TOKEN_KEYS_URI);

		Mockito.verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any());
		assertThat(firstKey).isNotNull();
		assertThat(secondKey).isNotNull();
		assertThat(thirdKey).isNotNull();
	}


	private class TestCacheTicker implements  Ticker {
		long elapsed = 0;

		@Override
		public long read() {
			return elapsed;
		}

		public void advance(long duration, TimeUnit unit) {
			this.elapsed = elapsed + unit.toNanos(duration);
		}
	}
}
