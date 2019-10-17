package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.*;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PasswordTokenFlowTest {

	private static final String USERNAME = "username";
	private static final String PASSWORD = "password";
	private static final URI TOKEN_ENDPOINT = TestConstants.xsuaaBaseUri;
	private static final ClientCredentials CLIENT_CREDENTIALS = new ClientCredentials(TestConstants.clientId,
			TestConstants.clientSecret);
	private static final String ACCESS_TOKEN = "abc123";
	private static final long EXPIRED_IN = 4223;
	private static final String REFRESH_TOKEN = "cba321";

	private OAuth2TokenService tokenService;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private PasswordTokenFlow cut;

	@Before
	public void setUp() throws OAuth2ServiceException {
		tokenService = Mockito.mock(OAuth2TokenService.class);
		endpointsProvider = Mockito.mock(OAuth2ServiceEndpointsProvider.class);

		when(endpointsProvider.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT);

		cut = new PasswordTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS);
	}

	@Test
	public void tokenServiceIsNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(null, endpointsProvider, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2TokenService");
	}

	@Test
	public void endpointsProviderIsNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(tokenService, null, CLIENT_CREDENTIALS))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void clientCredentialsAreNull_throwsException() {
		assertThatThrownBy(() -> new PasswordTokenFlow(tokenService, endpointsProvider, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ClientCredentials");
	}

	@Test
	public void usernameIsMissing_throwsException() {
		PasswordTokenFlow passwordTokenFlow = new PasswordTokenFlow(tokenService, endpointsProvider,
				CLIENT_CREDENTIALS);
		assertThatThrownBy(() -> passwordTokenFlow.password(PASSWORD).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Username");
	}

	@Test
	public void passwordIsMissing_throwsException() {
		PasswordTokenFlow passwordTokenFlow = new PasswordTokenFlow(tokenService, endpointsProvider,
				CLIENT_CREDENTIALS);
		assertThatThrownBy(() -> passwordTokenFlow.username(USERNAME).execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Password");
	}

	@Test
	public void requiredParametersGiven_returnsCorrectAccessTokenInResponse() throws Exception {
		returnValidResponse();

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getAccessToken()).isEqualTo(ACCESS_TOKEN);
	}

	@Test
	public void requiredParametersGiven_returnsRefreshTokenInResponse() throws Exception {
		returnValidResponse();

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
	}

	@Test
	public void requiredParametersGiven_returnsDifferentAccessTokenInResponse() throws Exception {
		String otherAccessToken = "effe123";
		returnValidResponse(otherAccessToken);

		OAuth2TokenResponse actualResponse = executeRequest();

		assertThat(actualResponse.getAccessToken()).isEqualTo(otherAccessToken);
	}

	@Test
	public void givenRequiredParameters_areUsed() throws Exception {
		executeRequest();

		Mockito.verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(eq(TOKEN_ENDPOINT), eq(CLIENT_CREDENTIALS), eq(USERNAME),
						eq(PASSWORD), any(), any());
	}

	@Test
	public void givenSubdomain_isUsed() throws Exception {
		createValidRequest().subdomain("staging").execute();

		Mockito.verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), eq("staging"), any());
	}

	@Test
	public void additionalParameters_areUsed() throws Exception {
		Map<String, String> givenParameters = Maps.newHashMap("aKey", "aValue");
		Map<String, String> equalParameters = Maps.newHashMap("aKey", "aValue");

		createValidRequest().optionalParameters(givenParameters).execute();

		Mockito.verify(tokenService, times(1))
				.retrieveAccessTokenViaPasswordGrant(any(), any(), any(),
						any(), any(), eq(equalParameters));
	}

	private OAuth2TokenResponse executeRequest() throws TokenFlowException {
		return createValidRequest().execute();
	}

	private PasswordTokenFlow createValidRequest() {
		return cut.username(USERNAME).password(PASSWORD);
	}

	private void returnValidResponse() throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(ACCESS_TOKEN, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT, CLIENT_CREDENTIALS, USERNAME, PASSWORD,
				null, null))
						.thenReturn(validResponse);
	}

	private void returnValidResponse(String accessToken) throws OAuth2ServiceException {
		OAuth2TokenResponse validResponse = new OAuth2TokenResponse(accessToken, EXPIRED_IN, REFRESH_TOKEN);
		when(tokenService.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT, CLIENT_CREDENTIALS, USERNAME, PASSWORD,
				null, null))
						.thenReturn(validResponse);
	}
}