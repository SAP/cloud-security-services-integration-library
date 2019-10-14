package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public class DefaultOAuth2TokenService extends AbstractOAuth2TokenService {

	private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2TokenService.class);

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenService() {
		this.httpClient = HttpClients.createDefault();
	}

	public DefaultOAuth2TokenService(CloseableHttpClient client) {
		this.httpClient = client;
	}

	@Override
	protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException {
		HttpPost httpPost = createHttpPost(tokenEndpointUri, headers, parameters);
		return executeRequest(httpPost);
	}

	private OAuth2TokenResponse executeRequest(HttpPost httpPost) throws OAuth2ServiceException {
		try {
			HttpResponse response = httpClient.execute(httpPost);
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
				return handleResponse(response);
			} else {
				String message = String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful!",
						response.getStatusLine().getStatusCode());
				throw new OAuth2ServiceException(message);
			}
		} catch (IOException e) {
			throw new OAuth2ServiceException("Unexpected error retrieving JWT token: " + e.getMessage());
		}
	}

	private OAuth2TokenResponse handleResponse(HttpResponse response) throws IOException {
		String responseAsString = convertToString(response);
		Map<String, Object> accessTokenMap = new JSONObject(responseAsString).toMap();
		logger.debug("Request Access Token: {}", accessTokenMap);
		return convertToOAuth2TokenResponse(accessTokenMap);
	}

	private String convertToString(HttpResponse response) throws IOException {
		return new BufferedReader(new InputStreamReader(response.getEntity().getContent()))
				.lines().collect(Collectors.joining(System.lineSeparator()));
	}

	private OAuth2TokenResponse convertToOAuth2TokenResponse(Map<String, Object> accessTokenMap)
			throws OAuth2ServiceException {
		String accessToken = getParameter(accessTokenMap, ACCESS_TOKEN);
		String refreshToken = getParameter(accessTokenMap, REFRESH_TOKEN);
		String expiresIn = getParameter(accessTokenMap, EXPIRES_IN);
		return new OAuth2TokenResponse(accessToken, Long.parseLong(expiresIn),
				refreshToken);
	}

	private String getParameter(Map<String, Object> accessTokenMap, String key) {
		return String.valueOf(accessTokenMap.get(key));
	}

	private HttpPost createHttpPost(URI uri, HttpHeaders headers, Map<String, String> parameters)
			throws OAuth2ServiceException {
		HttpPost httpPost = new HttpPost(uri);
		headers.getHeaders().forEach((header) -> httpPost.setHeader(header.getName(), header.getValue()));
		try {
			List<BasicNameValuePair> basicNameValuePairs = parameters.entrySet().stream()
					.map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
					.collect(Collectors.toList());
			httpPost.setEntity(new UrlEncodedFormEntity(basicNameValuePairs));
		} catch (UnsupportedEncodingException e) {
			throw new OAuth2ServiceException("Unexpected error parsing URI: " + e.getMessage());
		}
		return httpPost;
	}

}
