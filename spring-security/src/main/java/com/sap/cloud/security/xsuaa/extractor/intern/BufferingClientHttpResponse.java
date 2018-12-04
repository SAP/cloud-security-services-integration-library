package com.sap.cloud.security.xsuaa.extractor.intern;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;


final class BufferingClientHttpResponse implements ClientHttpResponse {

	private final ClientHttpResponse clientHttpResponse;

	private byte[] body;


	BufferingClientHttpResponse(ClientHttpResponse response) {
		this.clientHttpResponse = response;
	}


	public HttpStatus getStatusCode() throws IOException {
		return this.clientHttpResponse.getStatusCode();
	}

	public int getRawStatusCode() throws IOException {
		return this.clientHttpResponse.getRawStatusCode();
	}

	public String getStatusText() throws IOException {
		return this.clientHttpResponse.getStatusText();
	}

	public HttpHeaders getHeaders() {
		return this.clientHttpResponse.getHeaders();
	}

	public InputStream getBody() throws IOException {
		if (this.body == null) {
			this.body = StreamUtils.copyToByteArray(this.clientHttpResponse.getBody());
		}
		return new ByteArrayInputStream(this.body);
	}

	public void close() {
		this.clientHttpResponse.close();
	}

}