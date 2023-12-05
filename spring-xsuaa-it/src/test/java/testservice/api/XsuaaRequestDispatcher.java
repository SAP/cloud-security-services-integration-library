package testservice.api;

import com.sap.cloud.security.xsuaa.mock.JWTUtil;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class XsuaaRequestDispatcher extends Dispatcher {
	protected static final String RESPONSE_404 = "Xsuaa mock authorization server does not support this request";
	protected static final String RESPONSE_401 = "Xsuaa mock authorization server can't authenticate client/user";
	protected static final String RESPONSE_500 = "Xsuaa mock authorization server can't process request";
	protected static final String PATH_TESTDOMAIN_TOKEN_KEYS = "/mockServer/testdomain_token_keys.json";
	protected static final String PATH_PUBLIC_KEY = "/mockServer/publicKey.txt";
	protected final Logger logger = LoggerFactory.getLogger(XsuaaRequestDispatcher.class);
	private static int callCount = 0;

	@Override
	public MockResponse dispatch(RecordedRequest request) {
		callCount++;
		// mock JWKS endpoints
		if (request.getPath().contains("/token_keys?zid=testdomain")) {
			String subdomain = "testdomain";
			return getTokenKeyForKeyId(PATH_TESTDOMAIN_TOKEN_KEYS, "legacy-token-key-" + subdomain);
		}

		if (request.getPath().contains("/token_keys?zid=otherdomain")) {
			String subdomain = "otherdomain";
			return getTokenKeyForKeyId(PATH_TESTDOMAIN_TOKEN_KEYS, "legacy-token-key-" + subdomain);
		}

		if (request.getPath().contains("/token_keys")) {
			return getTokenKeyForKeyId(PATH_TESTDOMAIN_TOKEN_KEYS, "legacy-token-key");
		}

		// mock access token endpoints
		if (request.getPath().equals("/oauth/token") && "POST".equals(request.getMethod())) {
			String body = request.getBody().readString(StandardCharsets.UTF_8);
			if (body.contains("grant_type=password") && body.contains("username=basic.user")
					&& body.contains("password=basic.password")) {
				try {
					return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
							.setResponseCode(HttpStatus.OK.value())
							.setBody(String.format("{\"expires_in\": 43199, \"access_token\": \"%s\"}",
									JWTUtil.createJWT("/password.txt", "testdomain")));
				} catch (Exception e) {
					e.printStackTrace();
					getResponse(RESPONSE_500, HttpStatus.INTERNAL_SERVER_ERROR);
				}
			}
			if (body.contains("grant_type=client_credentials")) {
				try {
					return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
							.setResponseCode(HttpStatus.OK.value()).setBody(String.format(
									"{\"expires_in\": 43199, \"access_token\": \"%s\"}",
									JWTUtil.createJWT("/cc.txt", "testdomain")));
				} catch (Exception e) {
					e.printStackTrace();
					getResponse(RESPONSE_500, HttpStatus.INTERNAL_SERVER_ERROR);
				}
			}
			getResponse(RESPONSE_401, HttpStatus.UNAUTHORIZED);
		}

		return getResponse(RESPONSE_404, HttpStatus.NOT_FOUND);
	}

	protected MockResponse getResponseFromFile(String path, HttpStatus status) {
		try {
			String body = readFromFile(path);
			return getResponse(body, status);
		} catch (Exception e) {
			return getInternalErrorResponse(e.getMessage());
		}
	}

	protected MockResponse getResponse(String message, HttpStatus status) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(status.value())
				.setBody(message);
	}

	protected MockResponse getTokenKeyForKeyId(String pathToTemplate, String keyId) {
		try {
			String publicKey = readFromFile(PATH_PUBLIC_KEY);
			String body = readFromFile(pathToTemplate)
					.replace("$kid", keyId)
					.replace("$public_key", publicKey);
			return getResponse(body, HttpStatus.OK);
		} catch (Exception e) {
			return getInternalErrorResponse(e.getMessage());
		}
	}

	protected String readFromFile(String path) throws IOException {
		return IOUtils.resourceToString(path, StandardCharsets.UTF_8);
	}

	protected MockResponse getInternalErrorResponse(String message) {
		logger.warn(message);
		return getResponse(RESPONSE_500 + ": " + message, HttpStatus.INTERNAL_SERVER_ERROR);
	}

	public static int getCallCount() {
		return callCount;
	}
}
