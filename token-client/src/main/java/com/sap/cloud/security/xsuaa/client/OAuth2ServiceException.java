package com.sap.cloud.security.xsuaa.client;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Exception thrown to signal issues during communication with OAuth2 server.
 */
public class OAuth2ServiceException extends IOException {

	private static final long serialVersionUID = 1L;

	public OAuth2ServiceException(String message) {
		super(message);
	}

	public static OAuth2ServiceExceptionBuilder builder(String message) {
		return new OAuth2ServiceExceptionBuilder(message);
	}

	public static class OAuth2ServiceExceptionBuilder {
		private String message;
		private Integer statusCode;
		private URI serverUri;
		private String responseBody;

		public OAuth2ServiceExceptionBuilder(String message) {
			this.message = message;
		}

		public OAuth2ServiceExceptionBuilder withStatusCode(int statusCode) {
			this.statusCode = statusCode;
			return this;
		}

		public OAuth2ServiceExceptionBuilder withUri(URI serverUri) {
			this.serverUri = serverUri;
			return this;
		}

		public OAuth2ServiceExceptionBuilder withResponseBody(String responseBody) {
			this.responseBody = responseBody;
			return this;
		}

		public OAuth2ServiceException build() {
			String message = Stream
					.of(this.message, createUriMessage(), createStatusCodeMessage(), createResponseBodyMessage())
					.filter(Objects::nonNull)
					.collect(Collectors.joining(". "));
			return new OAuth2ServiceException(message);
		}

		private String createResponseBodyMessage() {
			return responseBody == null ? null : "Response body " + responseBody;
		}

		private String createStatusCodeMessage() {
			return statusCode == null ? null : "Status code " + statusCode;
		}

		private String createUriMessage() {
			return serverUri == null ? null : "Server URI " + serverUri;
		}

	}
}