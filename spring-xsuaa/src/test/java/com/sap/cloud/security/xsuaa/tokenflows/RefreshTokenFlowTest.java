package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.*;

@RunWith(MockitoJUnitRunner.class)
public class RefreshTokenFlowTest {

	@Mock
	private OAuth2TokenService mockTokenService;

	@Mock
	private VariableKeySetUriTokenDecoder mockTokenDecoder;

	private Jwt mockJwt;
	private ClientCredentials clientCredentials;
	private RefreshTokenFlow cut;

	private static final String JWT_ACCESS_TOKEN = "4bfad399ca10490da95c2b5eb4451d53";
	private static final String REFRESH_TOKEN = "99e2cecfa54f4957a782f07168915b69-r";

	@Before
	public void setup() {
		this.mockJwt = buildMockJwt();
		this.clientCredentials = new ClientCredentials("clientCredentials.getId()",
				"clientCredentials.getSecret()");
		this.cut = new RefreshTokenFlow(mockTokenService, mockTokenDecoder,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));

		Mockito.when(mockTokenDecoder.decode(JWT_ACCESS_TOKEN)).thenReturn(mockJwt);
	}

	private Jwt buildMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("dummyClaim", "dummyClaimValue");

		return new Jwt("mockJwtValue", Instant.now(),
				Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new RefreshTokenFlow(null, mockTokenDecoder,
					new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new RefreshTokenFlow(mockTokenService, null,
					new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("TokenDecoder");

		assertThatThrownBy(() -> {
			new RefreshTokenFlow(mockTokenService, mockTokenDecoder, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void execute_throwsIfMandatoryFieldsNotSet() {
		assertThatThrownBy(() -> {
			cut.execute();
		}).isInstanceOf(TokenFlowException.class);

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getId())
					.secret(clientCredentials.getSecret())
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("Refresh token not set");

		assertThatThrownBy(() -> {
			cut.client(null)
					.secret(clientCredentials.getSecret())
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client ID");

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getId())
					.secret(null)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client secret");
	}

	@Test
	public void execute() throws TokenFlowException {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(JWT_ACCESS_TOKEN, 441231);

		Mockito.when(mockTokenService
				.retrieveAccessTokenViaRefreshToken(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(REFRESH_TOKEN)))
				.thenReturn(accessToken);

		Jwt jwt = cut.client(clientCredentials.getId())
				.secret(clientCredentials.getSecret())
				.refreshToken(REFRESH_TOKEN)
				.execute();

		assertThat(jwt, is(mockJwt));
	}

	@Test
	public void execute_throwsIfServiceRaisesException() {
		Mockito.when(mockTokenService
				.retrieveAccessTokenViaRefreshToken(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(REFRESH_TOKEN)))
				.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getId())
					.secret(clientCredentials.getSecret())
					.refreshToken(REFRESH_TOKEN)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error refreshing token with grant_type 'refresh_token': exception executed REST call");
	}

}
