package com.sap.cloud.security.xsuaa.token.flows;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;

import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;

public class TokenDecoderMock implements VariableKeySetUriTokenDecoder {

	boolean setJwksURICalled;
	boolean decodeCalled;
	Jwt mockJwt;

	public TokenDecoderMock(Jwt mockJwt) {
		assertNotNull("TokenDecoder mock with null-token is bound to fail.", mockJwt);
		this.mockJwt = mockJwt;
	}

	@Override
	public void setJwksURI(URI keySetUri) {
		setJwksURICalled = true;
	}

	@Override
	public Jwt decode(String encodedValue) {
		assertNotNull("TokenDecoder decode called with null token value.", encodedValue);
		decodeCalled = true;
		return mockJwt;
	}

	public void validateCallstate() {
		assertTrue("setJwksURI was not called. Needs to be called to set the proper key set URI for token decoding.",
				setJwksURICalled);
		assertTrue("decode was not called. Needs to be called to decode token value into JWT token.", decodeCalled);
	}
}
