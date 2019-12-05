package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

public class SpringOidcConfigurationServiceTest {
	public static final URI CONFIG_ENDPOINT_URI = URI.create("https://sub.myauth.com" + DISCOVERY_ENDPOINT_DEFAULT);

	private RestOperations restOperationsMock;
	private SpringOidcConfigurationService cut;

	private final String jsonOidcConfiguration;

	public SpringOidcConfigurationServiceTest() throws IOException {
		jsonOidcConfiguration = IOUtils.resourceToString("/oidcConfiguration.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() throws Exception {
		restOperationsMock = mock(RestOperations.class);
		cut = new SpringOidcConfigurationService(restOperationsMock);
	}

	@Test
	public void restOperations_isNull_throwsException() {
		assertThatThrownBy(() -> new SpringOidcConfigurationService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_parameterIsNull_throwsException() throws OAuth2ServiceException {
		assertThatThrownBy(() -> retrieveEndpoints(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_badRequest_throwsException() {
		String errorDescription = "Something wen't wrong";
		mockResponse(errorDescription, HttpStatus.BAD_REQUEST);
		assertThatThrownBy(() -> retrieveEndpoints())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription);
	}

	@Test
	public void retrieveEndpoints_executesHttpGetRequestWithCorrectURI() throws OAuth2ServiceException {
		mockResponse();

		retrieveEndpoints();

		Mockito.verify(restOperationsMock, times(1))
				.getForEntity(CONFIG_ENDPOINT_URI, String.class);
	}

	@Test
	public void retrieveEndpoints_containsBothKeys() throws OAuth2ServiceException {
		mockResponse();

		OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

		assertThat(result.getTokenEndpoint().toString()).isEqualTo("http://localhost/oauth/token");
		assertThat(result.getJwksUri().toString()).isEqualTo("http://localhost/token_keys");
		assertThat(result.getAuthorizeEndpoint().toString()).isEqualTo("http://localhost/oauth/authorize");
	}

	private void mockResponse() {
		mockResponse(jsonOidcConfiguration, HttpStatus.OK);
	}

	private void mockResponse(String responseAsString, HttpStatus httpStatus) {
		ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(responseAsString, httpStatus);
		when(restOperationsMock.getForEntity(any(URI.class), eq(String.class)))
				.thenReturn(stringResponseEntity);
	}

	private OAuth2ServiceEndpointsProvider retrieveEndpoints() throws OAuth2ServiceException {
		return retrieveEndpoints(CONFIG_ENDPOINT_URI);
	}

	private OAuth2ServiceEndpointsProvider retrieveEndpoints(URI endpointsEndpointUri) throws OAuth2ServiceException {
		return cut.retrieveEndpoints(endpointsEndpointUri);
	}
}