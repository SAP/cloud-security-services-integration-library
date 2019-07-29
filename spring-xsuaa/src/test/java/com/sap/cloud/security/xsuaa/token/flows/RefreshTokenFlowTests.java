package com.sap.cloud.security.xsuaa.token.flows;

import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addAcceptHeader;
import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addBasicAuthHeader;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.RefreshTokenFlow;
import com.sap.cloud.security.xsuaa.token.flows.TokenFlowException;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;

public class RefreshTokenFlowTests {

	private RestTemplate restTemplate;
	private VariableKeySetUriTokenDecoder tokenDecoder;
	private String refreshToken;

	private TokenDecoderMock tokenDecoderMock;
	private Jwt mockJwt;
	private String clientId = "clientId";
	private String clientSecret = "clientSecret";

	@Before
	public void setup() {
		this.restTemplate = new RestTemplate();
		this.tokenDecoder = new NimbusTokenDecoder();
		this.refreshToken = "dummyRefreshToken";

		this.mockJwt = buildMockJwt();
		this.tokenDecoderMock = new TokenDecoderMock(mockJwt);
	}

	private Jwt buildMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("dummyClaim", "dummyClaimValue");

		return new Jwt("mockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}

	@Test
	public void test_constructor_withBaseURI() throws TokenFlowException {
		new RefreshTokenFlow(restTemplate, tokenDecoder, TestConstants.xsuaaBaseUri);
	}

	@Test
	public void test_constructor_withEndpointURIs() throws TokenFlowException {
		new RefreshTokenFlow(restTemplate, tokenDecoder, TestConstants.tokenEndpointUri,
				TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
	}

	@Test
	public void test_constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new RefreshTokenFlow(null, tokenDecoder, TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RestTemplate");

		assertThatThrownBy(() -> {
			new RefreshTokenFlow(restTemplate, null, TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("TokenDecoder");

		assertThatThrownBy(() -> {
			new RefreshTokenFlow(restTemplate, tokenDecoder, null, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("Token endpoint");

		assertThatThrownBy(() -> {
			new RefreshTokenFlow(restTemplate, tokenDecoder, TestConstants.tokenEndpointUri, null,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("Authorize");

		assertThatThrownBy(() -> {
			new RefreshTokenFlow(restTemplate, tokenDecoder, TestConstants.tokenEndpointUri,
					TestConstants.authorizeEndpointUri, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("Key set");
	}

	@Test
	public void test_execute_throwsIfMandatoryFieldsNotSet() {

		assertThatThrownBy(() -> {
			RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplate, tokenDecoder,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.execute();
		}).isInstanceOf(TokenFlowException.class);

		assertThatThrownBy(() -> {
			RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplate, tokenDecoder,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("Refresh token not set");

		assertThatThrownBy(() -> {
			RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplate, tokenDecoder,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.refreshToken("dummy")
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("Refresh token flow request is not valid");

		assertThatThrownBy(() -> {
			RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplate, tokenDecoder,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.client(null)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client ID");

		assertThatThrownBy(() -> {
			RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplate, tokenDecoder,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.client(clientId)
					.secret(null)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client secret");
	}

	@Test
	public void test_execute() throws TokenFlowException {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId, clientSecret);

		URI expectedRequestURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "refresh_token")
				.queryParam("refresh_token", refreshToken)
				.build().toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI, expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.OK);

		RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplateMock, tokenDecoderMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
		tokenFlow.refreshToken(refreshToken)
				.client(clientId)
				.secret(clientSecret)
				.execute();

		restTemplateMock.validateCallstate();
		tokenDecoderMock.validateCallstate();
	}

	@Test
	public void test_execute_throwsIfHttpStatusUnauthorized() throws TokenFlowException {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId, clientSecret);

		URI expectedRequestURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "refresh_token")
				.queryParam("refresh_token", refreshToken)
				.build().toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI, expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.UNAUTHORIZED);

		RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplateMock, tokenDecoderMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);

		assertThatThrownBy(() -> {
			tokenFlow.refreshToken(refreshToken)
					.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(String.format("Received status code %s", HttpStatus.UNAUTHORIZED));
	}

	@Test
	public void test_execute_throwsIfHttpStatusIsNotOK() {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId, clientSecret);

		URI expectedRequestURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "refresh_token")
				.queryParam("refresh_token", refreshToken)
				.build().toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI, expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.CONFLICT);

		RefreshTokenFlow tokenFlow = new RefreshTokenFlow(restTemplateMock, tokenDecoderMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);

		assertThatThrownBy(() -> {
			tokenFlow.refreshToken(refreshToken)
					.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(String.format("Received status code %s", HttpStatus.CONFLICT));
	}

	private HttpEntity<Void> buildExpectedRequest(String clientId, String clientSecret) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addBasicAuthHeader(headers, clientId, clientSecret);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
		return requestEntity;
	}
}
