package com.sap.cloud.security.test;

import com.sap.cloud.security.xsuaa.http.MediaType;
import org.apache.commons.io.IOUtils;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;

public class TokenKeyServlet extends HttpServlet {

	private final PublicKey publicKey;

	public TokenKeyServlet(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType(MediaType.APPLICATION_JSON.value());
		response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
		response.getWriter().write(createDefaultTokenKeyResponse());
	}

	private String createDefaultTokenKeyResponse() throws IOException {
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", "default-kid")
				.replace("$public_key", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
	}
}
