package com.sap.cloud.security.xsuaa.extractor.intern;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

public class LoggerInterceptor implements ClientHttpRequestInterceptor {
	private Log log;
	private List<String> doNotTraceRequestList = Arrays.asList(new String[] { "/oauth/clients", "/oauth/token", "/check_token" });

	public LoggerInterceptor(Log log) {
		this.log = log;
	}

	public static List<ClientHttpRequestInterceptor> getInterceptor(Log log) {
		return Arrays.<ClientHttpRequestInterceptor> asList(new LoggerInterceptor(log));
	}

	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {

		ClientHttpResponse response = execution.execute(request, body);
		if (!response.getStatusCode().is2xxSuccessful()) {
			boolean doNotTrace = false;
			for (String doNotTraceRequest : doNotTraceRequestList)
				if (request.getURI().getPath().contains(doNotTraceRequest)) {
					doNotTrace = true;
				}
			if (doNotTrace) {
				log.warn(String.format("REQUEST: %s to URI %s with payload %s", request.getMethod(), request.getURI(), "<sensitive content>"));
			} else {
				log.warn(String.format("REQUEST: %s to URI %s with payload %s", request.getMethod(), request.getURI(), new String(body, "UTF-8")));
			}
			response = traceResponse(response);
		}

		return response;
	}

	private BufferingClientHttpResponse traceResponse(ClientHttpResponse response) throws IOException {
		BufferingClientHttpResponse copiedResponse = new BufferingClientHttpResponse(response);

		String responseBody = null;
		try {
			StringBuilder inputStringBuilder = new StringBuilder();
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(copiedResponse.getBody(), "UTF-8"));
			String line = bufferedReader.readLine();
			while (line != null) {
				inputStringBuilder.append(line);
				inputStringBuilder.append('\n');
				line = bufferedReader.readLine();
			}
			responseBody = inputStringBuilder.toString();
		} catch (IOException e) {
			log.trace(e.getMessage(), e);
		}
		String msg = String.format("RESPONSE: %s (%s) with payload %s", copiedResponse.getStatusCode(), copiedResponse.getStatusText(), responseBody);

		log.warn(msg);
		return copiedResponse;
	}
}