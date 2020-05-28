package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class DefaultOAuth2TokenServiceTest {

	private static final String ACCESS_TOKEN = "abc123";
	private static final String REFRESH_TOKEN = "def456";
	private static final String VALID_JSON_RESPONSE = String
			.format("{expires_in: 10000, access_token: %s, refresh_token: %s}",
					ACCESS_TOKEN, REFRESH_TOKEN);

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

		assertThatThrownBy(() -> requestAccessToken(Collections.emptyMap()))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining("expires_in");
	}

	@Test
	public void execute_yieldsTokenResponseWithCorrectData() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		OAuth2TokenResponse re = requestAccessToken(Collections.emptyMap());

		assertThat(re.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		assertThat(re.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
		assertThat(re.getExpiredAt()).isAfter(Instant.now());
	}

	@Test
	public void executeWithAdditionalParameters_putsParametersIntoPostBody() throws IOException {
		ArgumentCaptor<HttpPost> httpPostCaptor = ArgumentCaptor.forClass(HttpPost.class);
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		requestAccessToken(Maps.newHashMap("myKey", "myValue"));

		verify(mockHttpClient, times(1)).execute(httpPostCaptor.capture());
		HttpPost httpPost = httpPostCaptor.getValue();
		HttpEntity httpEntity = httpPost.getEntity();
		assertThat(httpEntity).isNotNull();
		String postBody = IOUtils.toString(httpEntity.getContent(), StandardCharsets.UTF_8);
		assertThat(postBody).contains("myKey=myValue");
	}

	@Test
	public void httpResponseWithErrorStatusCode_throwsExceptionContainingMessage() throws IOException {
		String unauthorizedResponseText = "Unauthorized!";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(unauthorizedResponseText, HttpStatus.SC_UNAUTHORIZED);
		when(mockHttpClient.execute(any(HttpPost.class))).thenReturn(response);

		assertThatThrownBy(() -> requestAccessToken(Collections.emptyMap()))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(unauthorizedResponseText);
	}

	private OAuth2TokenResponse requestAccessToken(Map<String, String> parameters) throws OAuth2ServiceException {
		URI tokenEndpointUri = URI.create("https://subdomain.myauth.server.com/oauth/token");
		HttpHeaders withoutAuthorizationHeader = HttpHeadersFactory.createWithoutAuthorizationHeader();
		return cut.requestAccessToken(tokenEndpointUri, withoutAuthorizationHeader, parameters);
	}

}