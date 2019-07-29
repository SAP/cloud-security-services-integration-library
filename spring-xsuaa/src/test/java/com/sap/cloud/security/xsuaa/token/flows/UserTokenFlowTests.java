package com.sap.cloud.security.xsuaa.token.flows;

import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addAcceptHeader;
import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.addAuthorizationBearerHeader;
import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.buildAdditionalAuthoritiesJson;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sap.cloud.security.xsuaa.token.flows.TokenFlowException;
import com.sap.cloud.security.xsuaa.token.flows.UserTokenFlow;

public class UserTokenFlowTests {

	private RestTemplate restTemplate;
	private Jwt invalidMockJwt;
	private Jwt validMockJwt;
	private String clientId = "clientId";
	private String clientSecret = "clientSecret";
	private RefreshTokenFlowMock refreshTokenFlowMock;

	@Before
	public void setup() {
		this.restTemplate = new RestTemplate();

		this.invalidMockJwt = buildInvalidMockJwt();
		this.validMockJwt = buildValidMockJwt();

		this.refreshTokenFlowMock = new RefreshTokenFlowMock(validMockJwt);
	}

	private Jwt buildInvalidMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("scope", Arrays.asList("read", "write")); // no uaa.user scope!

		return new Jwt("InvalidMockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}

	private Jwt buildValidMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("scope", Arrays.asList("uaa.user", "read", "write")); // got the uaa.user scope!

		return new Jwt("ValidMockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}

	@Test
	public void test_constructor_withBaseURI() throws TokenFlowException {
		new UserTokenFlow(restTemplate, refreshTokenFlowMock, TestConstants.xsuaaBaseUri);
	}

	@Test
	public void test_constructor_withEndpointURIs() throws TokenFlowException {
		new UserTokenFlow(restTemplate, refreshTokenFlowMock, TestConstants.tokenEndpointUri,
				TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
	}

	@Test
	public void test_constructor_throwsOnNullValues() {

		assertThatThrownBy(() -> {
			new UserTokenFlow(null, refreshTokenFlowMock, TestConstants.xsuaaBaseUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RestTemplate");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, null, TestConstants.xsuaaBaseUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RefreshTokenFlow");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, refreshTokenFlowMock, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("XSUAA base URI");

		assertThatThrownBy(() -> {
			new UserTokenFlow(null, refreshTokenFlowMock, TestConstants.tokenEndpointUri,
					TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RestTemplate");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, null, TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RefreshTokenFlow");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, refreshTokenFlowMock, null, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("Token endpoint");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, refreshTokenFlowMock, TestConstants.tokenEndpointUri, null,
					TestConstants.keySetEndpointUri);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("Authorize");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, refreshTokenFlowMock, TestConstants.tokenEndpointUri,
					TestConstants.authorizeEndpointUri, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("Key set");
	}

	@Test
	public void test_execute_throwsIfTokenDoesNotContainUaaUserScope() {

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, refreshTokenFlowMock, TestConstants.xsuaaBaseUri)
					.token(invalidMockJwt)
					.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("JWT token does not include scope 'uaa.user'");

		assertThatThrownBy(() -> {
			new UserTokenFlow(restTemplate, refreshTokenFlowMock, TestConstants.tokenEndpointUri,
					TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri)
							.token(invalidMockJwt)
							.client(clientId)
							.secret(clientSecret)
							.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("JWT token does not include scope 'uaa.user'");
	}

	@Test
	public void test_execute_throwsIfMandatoryFieldsNotSet() {

		assertThatThrownBy(() -> {
			UserTokenFlow tokenFlow = new UserTokenFlow(restTemplate, refreshTokenFlowMock,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.execute();
		}).isInstanceOf(TokenFlowException.class);

		assertThatThrownBy(() -> {
			UserTokenFlow tokenFlow = new UserTokenFlow(restTemplate, refreshTokenFlowMock,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.token(validMockJwt)
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("User token flow request is not valid");

		assertThatThrownBy(() -> {
			UserTokenFlow tokenFlow = new UserTokenFlow(restTemplate, refreshTokenFlowMock,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("User token not set");

		assertThatThrownBy(() -> {
			UserTokenFlow tokenFlow = new UserTokenFlow(restTemplate, refreshTokenFlowMock,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.client(null)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client ID");

		assertThatThrownBy(() -> {
			UserTokenFlow tokenFlow = new UserTokenFlow(restTemplate, refreshTokenFlowMock,
					TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri,
					TestConstants.keySetEndpointUri);
			tokenFlow.client(clientId)
					.secret(null)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client secret");
	}

	@Test
	public void test_execute() throws TokenFlowException {

		URI expectedRequestURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "user_token")
				.queryParam("response_type", "token")
				.queryParam("client_id", clientId)
				.build().toUri();

		HttpEntity<Void> expectedRequest = buildExpectedRequest();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI, expectedRequest, Map.class,
				validMockJwt.getTokenValue(), HttpStatus.OK);

		UserTokenFlow tokenFlow = new UserTokenFlow(restTemplateMock, refreshTokenFlowMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
		tokenFlow.token(validMockJwt)
				.client(clientId)
				.secret(clientSecret)
				.execute();

		restTemplateMock.validateCallstate();
		refreshTokenFlowMock.validateCallstate();
	}

	@Test
	public void test_execute_throwsIfHttpStatusUnauthorized() throws TokenFlowException {

		URI expectedRequestURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "user_token")
				.queryParam("response_type", "token")
				.queryParam("client_id", clientId)
				.build().toUri();

		HttpEntity<Void> expectedRequest = buildExpectedRequest();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI, expectedRequest, Map.class,
				validMockJwt.getTokenValue(), HttpStatus.UNAUTHORIZED);

		UserTokenFlow tokenFlow = new UserTokenFlow(restTemplateMock, refreshTokenFlowMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);

		assertThatThrownBy(() -> {
			tokenFlow.token(validMockJwt)
					.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(String.format("Received status code %s", HttpStatus.UNAUTHORIZED));
	}

	@Test
	public void test_execute_throwsIfHttpStatusIsNotOK() {

		URI expectedRequestURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "user_token")
				.queryParam("response_type", "token")
				.queryParam("client_id", clientId)
				.build().toUri();

		HttpEntity<Void> expectedRequest = buildExpectedRequest();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI, expectedRequest, Map.class,
				validMockJwt.getTokenValue(), HttpStatus.CONFLICT);

		UserTokenFlow tokenFlow = new UserTokenFlow(restTemplateMock, refreshTokenFlowMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);

		assertThatThrownBy(() -> {
			tokenFlow.token(validMockJwt)
					.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(String.format("Received status code %s", HttpStatus.CONFLICT));
	}

	@Test
	public void test_execute_withAdditionalAuthorities() throws TokenFlowException, JsonProcessingException {

		HttpEntity<Void> expectedRequest = buildExpectedRequest();

		Map<String, String> additionalAuthorities = new HashMap<String, String>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");
		String authorities = buildAdditionalAuthoritiesJson(additionalAuthorities); // returns JSON!

		URI expectedURI = UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
				.queryParam("grant_type", "user_token")
				.queryParam("response_type", "token")
				.queryParam("client_id", clientId)
				.queryParam("authorities", authorities)
				.build()
				.encode()
				.toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedURI, expectedRequest, Map.class,
				validMockJwt.getTokenValue(), HttpStatus.OK);

		UserTokenFlow tokenFlow = new UserTokenFlow(restTemplateMock, refreshTokenFlowMock,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
		tokenFlow.token(validMockJwt)
				.client(clientId)
				.secret(clientSecret)
				.attributes(additionalAuthorities)
				.execute();

		restTemplateMock.validateCallstate();
		refreshTokenFlowMock.validateCallstate();
	}

	private HttpEntity<Void> buildExpectedRequest() {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addAuthorizationBearerHeader(headers, validMockJwt);
		return new HttpEntity<>(headers);
	}
}
