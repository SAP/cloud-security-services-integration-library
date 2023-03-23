/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
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
	private Integer httpStatusCode = 0;

	public OAuth2ServiceException(String message) {
		super(message);
	}

	/**
	 * Creates an exception.
	 *
	 * @param message
	 *            the error message
	 * @param httpStatusCode
	 *            the status code of the HTTP service request
	 */
	public OAuth2ServiceException(String message, Integer httpStatusCode) {
		super(message);
		this.httpStatusCode = httpStatusCode != null ? httpStatusCode : 0;
	}

	/**
	 * Creates an exception.
	 *
	 * @param message
	 *            the error message
	 */
	public static Builder builder(String message) {
		return new Builder(message);
	}

	/**
	 * Returns the HTTP status code of the failed OAuth2 service request or
	 * {@code 0} e.g. in case the service wasn't called at all.
	 *
	 * @return status code or 0
	 */
	public Integer getHttpStatusCode() {
		return httpStatusCode;
	}

	public static class Builder {
		private String message;
		private Integer httpStatusCode;
		private URI serverUri;
		private String responseBody;
		private String headers;

		public Builder(String message) {
			this.message = message;
		}

		/**
		 * Parameterizes the Exception with a HTTP status code.
		 *
		 * @param httpStatusCode
		 *            the http status code
		 * @return the builder
		 */
		public Builder withStatusCode(int httpStatusCode) {
			this.httpStatusCode = httpStatusCode;
			return this;
		}

		public Builder withUri(URI serverUri) {
			this.serverUri = serverUri;
			return this;
		}

		public Builder withUri(String requestUri) {
			withUri(URI.create(requestUri));
			return this;
		}

		public Builder withResponseBody(String responseBody) {
			this.responseBody = responseBody;
			return this;
		}

		public Builder withHeaders(String... headers) {
			this.headers = "[";
			for (String header : headers) {
				this.headers += header;
			}
			this.headers += "]";
			return this;
		}

		public OAuth2ServiceException build() {
			String message = Stream
					.of(this.message, createUriMessage(), createStatusCodeMessage(), createResponseBodyMessage(),
							createHeaderMessage())
					.filter(Objects::nonNull)
					.collect(Collectors.joining(". "));
			return new OAuth2ServiceException(message, httpStatusCode);
		}

		private String createResponseBodyMessage() {
			return responseBody == null ? null : "Response body '" + responseBody + "'";
		}

		private String createStatusCodeMessage() {
			return httpStatusCode == null ? null : "Http status code " + httpStatusCode;
		}

		private String createUriMessage() {
			return serverUri == null ? null : "Server URI " + serverUri;
		}

		private String createHeaderMessage() {
			return headers == null ? null : "Headers " + headers;
		}
	}
}