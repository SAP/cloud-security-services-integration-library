package com.sap.cloud.security.xsuaa.tokenflows;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;

@RunWith(MockitoJUnitRunner.class)
public class UserTokenFlowTest {

	private OAuth2TokenService mockTokenService;

	private final String exchangeToken = "exchange token";
	private final ClientCredentials clientCredentials = new ClientCredentials("clientId", "clientSecret");
	private final OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(XSUAA_BASE_URI);

	private UserTokenFlow cut;

	@Before
	public void setup() {
		this.mockTokenService = mock(OAuth2TokenService.class);
		this.cut = new UserTokenFlow(mockTokenService, endpointsProvider, clientCredentials);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new UserTokenFlow(null, endpointsProvider, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, null, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, endpointsProvider, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientCredentials");
	}

	@Test
	public void execute_throwsIfMandatoryFieldsNotSet() {
		assertThatThrownBy(cut::execute)
				.isInstanceOf(IllegalStateException.class);

		assertThatThrownBy(cut::execute)
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("User token not set");
	}

	@Test
	public void execute_throwsIfServiceRaisesException() throws OAuth2ServiceException {
		when(mockTokenService
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), isNull(), isNull(), anyBoolean()))
						.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> cut.token(exchangeToken).execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error requesting token with grant_type 'urn:ietf:params:oauth:grant-type:jwt-bearer'");
	}

	@Test
	public void execute_callsServiceWithDefaults() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.token(exchangeToken).execute();

		assertThat(response.getAccessToken(), is(mockedResponse.getAccessToken()));
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(endpointsProvider.getTokenEndpoint(),
						clientCredentials, exchangeToken, null,
						null, false);
	}

	@Test
	public void execute_withSubdomain() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();
		String subdomain = "subdomain";

		OAuth2TokenResponse response = cut.subdomain(subdomain).token(exchangeToken).execute();

		assertThat(response.getAccessToken(), is(mockedResponse.getAccessToken()));
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), eq(subdomain), any(), anyBoolean());
	}

	@Test
	public void execute_withDisableCache() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.disableCache(true).token(exchangeToken).execute();

		assertThat(response.getAccessToken(), is(mockedResponse.getAccessToken()));
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), any(), eq(true));

		cut.disableCache(false).token(exchangeToken).execute();

		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), any(), eq(false));
	}

	@Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		Map<String, String> additionalAuthorities = new HashMap<String, String>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");
		Map<String, String> additionalAuthoritiesParam = new HashMap<>();
		additionalAuthoritiesParam.put("authorities", "{\"az_attr\":{\"DummyAttribute\":\"DummyAttributeValue\"}}");

		OAuth2TokenResponse actualResponse = cut.token(exchangeToken)
				.attributes(additionalAuthorities)
				.execute();

		assertThat(actualResponse.getAccessToken(), is(mockedResponse.getAccessToken()));
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(clientCredentials),
						eq(exchangeToken),
						isNull(), eq(additionalAuthoritiesParam), anyBoolean());
	}

	private OAuth2TokenResponse mockRetrieveAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse tokenResponse = new OAuth2TokenResponse("4bfad399ca10490da95c2b5eb4451d53",
				441231, REFRESH_TOKEN);
		when(mockTokenService.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI),
				eq(clientCredentials),
				eq(exchangeToken),
				any(), any(), anyBoolean()))
						.thenReturn(tokenResponse);
		return tokenResponse;
	}

}