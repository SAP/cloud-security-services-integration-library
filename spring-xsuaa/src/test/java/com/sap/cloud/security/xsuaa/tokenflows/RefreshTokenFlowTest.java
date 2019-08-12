// package com.sap.cloud.security.xsuaa.tokenflows;
//
// import com.sap.cloud.security.xsuaa.client.OAuth2Service;
// import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
// import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
// import org.junit.Before;
// import org.junit.Test;
// import org.springframework.http.HttpEntity;
// import org.springframework.http.HttpHeaders;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.MediaType;
// import org.springframework.security.oauth2.jwt.Jwt;
// import org.springframework.web.client.RestTemplate;
// import org.springframework.web.util.UriComponentsBuilder;
//
// import java.net.URI;
// import java.time.Instant;
// import java.util.HashMap;
// import java.util.Map;
//
// import static org.assertj.core.api.Assertions.assertThatThrownBy;
//
// public class RefreshTokenFlowTest {
//
// private OAuth2TokenService tokenService;
// private VariableKeySetUriTokenDecoder tokenDecoder;
// private String refreshToken;
//
// private TokenDecoderMock tokenDecoderMock;
// private Jwt mockJwt;
// private String clientId = "clientId";
// private String clientSecret = "clientSecret";
//
// @Before
// public void setup() {
// this.tokenService = new OAuth2Service(new RestTemplate());
// this.tokenDecoder = new NimbusTokenDecoder();
// this.refreshToken = "dummyRefreshToken";
//
// this.mockJwt = buildMockJwt();
// this.tokenDecoderMock = new TokenDecoderMock(mockJwt);
// }
//
// private Jwt buildMockJwt() {
// Map<String, Object> jwtHeaders = new HashMap<String, Object>();
// jwtHeaders.put("dummyHeader", "dummyHeaderValue");
//
// Map<String, Object> jwtClaims = new HashMap<String, Object>();
// jwtClaims.put("dummyClaim", "dummyClaimValue");
//
// return new Jwt("mockJwtValue", Instant.now(),
// Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
// }
//
// @Test
// public void test_constructor_withBaseURI() throws TokenFlowException {
// createTokenFlow();
// }
//
// private RefreshTokenFlow createTokenFlow() {
// return new RefreshTokenFlow(tokenService, tokenDecoder, new
// XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
// }
//
// @Test
// public void test_execute_throwsIfMandatoryFieldsNotSet() {
//
// assertThatThrownBy(() -> {
// RefreshTokenFlow tokenFlow = createTokenFlow();
// tokenFlow.execute();
// }).isInstanceOf(TokenFlowException.class);
//
// assertThatThrownBy(() -> {
// RefreshTokenFlow tokenFlow = createTokenFlow();
// tokenFlow.client(clientId)
// .secret(clientSecret)
// .execute();
// }).isInstanceOf(TokenFlowException.class).hasMessageContaining("Refresh token
// not set");
//
// assertThatThrownBy(() -> {
// RefreshTokenFlow tokenFlow = createTokenFlow();
// tokenFlow.refreshToken("dummy")
// .execute();
// }).isInstanceOf(TokenFlowException.class).hasMessageContaining("Refresh token
// flow request is not valid");
//
// assertThatThrownBy(() -> {
// RefreshTokenFlow tokenFlow = createTokenFlow();
// tokenFlow.client(null)
// .secret(clientSecret)
// .execute();
// }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client
// ID");
//
// assertThatThrownBy(() -> {
// RefreshTokenFlow tokenFlow = createTokenFlow();
// tokenFlow.client(clientId)
// .secret(null)
// .execute();
// }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client
// secret");
// }
//
// @Test
// public void test_execute() throws TokenFlowException {
//
// HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
// clientSecret);
//
// URI expectedRequestURI =
// UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
// .queryParam("refresh_token", refreshToken)
// .queryParam("grant_type", "refresh_token")
// .build().toUri();
//
// RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI,
// expectedRequest, Map.class,
// mockJwt.getTokenValue(), HttpStatus.OK);
//
// RefreshTokenFlow tokenFlow = new RefreshTokenFlow(new
// OAuth2Service(restTemplateMock),
// tokenDecoderMock,
// new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
// tokenFlow.refreshToken(refreshToken)
// .client(clientId)
// .secret(clientSecret)
// .execute();
//
// restTemplateMock.validateCallstate();
// tokenDecoderMock.validateCallstate();
// }
//
// @Test
// public void test_execute_throwsIfHttpStatusUnauthorized() throws
// TokenFlowException {
//
// HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
// clientSecret);
//
// URI expectedRequestURI =
// UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
// .queryParam("grant_type", "refresh_token")
// .queryParam("refresh_token", refreshToken)
// .build().toUri();
//
// RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI,
// expectedRequest, Map.class,
// mockJwt.getTokenValue(), HttpStatus.UNAUTHORIZED);
//
// RefreshTokenFlow tokenFlow = new RefreshTokenFlow(new
// OAuth2Service(restTemplateMock),
// tokenDecoderMock,
// new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
//
// assertThatThrownBy(() -> {
// tokenFlow.refreshToken(refreshToken)
// .client(clientId)
// .secret(clientSecret)
// .execute();
// }).isInstanceOf(TokenFlowException.class)
// .hasMessageContaining(String.format("Received status code %s",
// HttpStatus.UNAUTHORIZED));
// }
//
// @Test
// public void test_execute_throwsIfHttpStatusIsNotOK() {
//
// HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
// clientSecret);
//
// URI expectedRequestURI =
// UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
// .queryParam("grant_type", "refresh_token")
// .queryParam("refresh_token", refreshToken)
// .build().toUri();
//
// RestTemplateMock restTemplateMock = new RestTemplateMock(expectedRequestURI,
// expectedRequest, Map.class,
// mockJwt.getTokenValue(), HttpStatus.CONFLICT);
//
// RefreshTokenFlow tokenFlow = new RefreshTokenFlow(new
// OAuth2Service(restTemplateMock),
// tokenDecoderMock,
// new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
//
// assertThatThrownBy(() -> {
// tokenFlow.refreshToken(refreshToken)
// .client(clientId)
// .secret(clientSecret)
// .execute();
// }).isInstanceOf(TokenFlowException.class)
// .hasMessageContaining(String.format("Received status code %s",
// HttpStatus.CONFLICT));
// }
//
// private HttpEntity<Void> buildExpectedRequest(String clientId, String
// clientSecret) {
// HttpHeaders headers = new HttpHeaders();
// headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
// headers.add("Authorization", "Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0");
// HttpEntity<Void> expectedRequest = new HttpEntity<>(headers);
// return expectedRequest;
// }
// }
