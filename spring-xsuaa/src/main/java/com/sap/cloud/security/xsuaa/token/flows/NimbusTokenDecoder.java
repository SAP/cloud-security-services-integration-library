package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

/**
 * A default {@link VariableKeySetUriTokenDecoder} implementation using
 * {@link NimbusJwtDecoderJwkSupport} as the implementation class.
 */
public class NimbusTokenDecoder implements VariableKeySetUriTokenDecoder {

	private NimbusJwtDecoderJwkSupport nimbusDecoder;

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.sap.cloud.address.service.xsuaa.tokenflows.TokenDecoder#setJwksURI(java.
	 * net.URI)
	 */
	@Override
	public void setJwksURI(URI keySetUri) {
		this.nimbusDecoder = new NimbusJwtDecoderJwkSupport(keySetUri.toString());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.sap.cloud.address.service.xsuaa.tokenflows.TokenDecoder#decode(java.lang.
	 * String)
	 */
	@Override
	public Jwt decode(String encodedValue) {
		if (nimbusDecoder == null) {
			throw new IllegalStateException(
					"Nimbus decoder not properly initialized. Make sure setJwksUri() is called before calling decode().");
		}
		return this.nimbusDecoder.decode(encodedValue);
	}
}
