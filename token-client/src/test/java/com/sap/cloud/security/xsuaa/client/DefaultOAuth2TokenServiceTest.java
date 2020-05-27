package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DefaultOAuth2TokenServiceTest {

	private static final String ACCESS_TOKEN = "abc123";
	private static final String REFRESH_TOKEN = "def456";
	private static final String VALID_JSON_RESPONSE = String
			.format("{expires_in: 1234, access_token: %s, refresh_token: %s}",
					ACCESS_TOKEN, REFRESH_TOKEN);
	private static final URI TOKEN_ENDPOINT_URI = URI.create("https://subdomain.myauth.server.com/oauth/token");

	private CloseableHttpClient mockHttpClient;
	private DefaultOAuth2TokenService cut;

	@Before
	public void setup() {
		mockHttpClient = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOAuth2TokenService(mockHttpClient);
	}

	@Test
	public void emptyResponse_throwsException() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse("{}");
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		assertThatThrownBy(() -> requestAccessToken())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining("expires_in");
	}

	@Test
	public void httpResponseWithExpiresIn_yieldsExpiresInTokenResponse() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		OAuth2TokenResponse re = requestAccessToken();

		assertThat(re.getExpiredAtDate()).isNotNull();
	}

	@Test
	public void httpResponseWithToken_yieldsTokenInTokenResponse() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		OAuth2TokenResponse re = requestAccessToken();

		assertThat(re.getAccessToken()).isEqualTo(ACCESS_TOKEN);
	}

	@Test
	public void httpResponseWithRefreshToken_yieldsTokenInTokenResponse() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		OAuth2TokenResponse re = requestAccessToken();

		assertThat(re.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
	}

	@Test
	public void httpResponseWithErrorStatusCode_throwsExceptionContainingMessage() throws IOException {
		String unauthorizedResponseText = "Unauthorized!";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(unauthorizedResponseText, HttpStatus.SC_UNAUTHORIZED);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		assertThatThrownBy(() -> requestAccessToken())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(unauthorizedResponseText)
				.hasMessageContaining(String.valueOf(HttpStatus.SC_UNAUTHORIZED))
				.hasMessageContaining(TOKEN_ENDPOINT_URI.toString());
	}

	private OAuth2TokenResponse requestAccessToken() throws OAuth2ServiceException {
		HttpHeaders withoutAuthorizationHeader = HttpHeadersFactory.createWithoutAuthorizationHeader();
		Map<String, String> parameters = Collections.emptyMap();
		return cut.requestAccessToken(TOKEN_ENDPOINT_URI, withoutAuthorizationHeader, parameters);
	}

}