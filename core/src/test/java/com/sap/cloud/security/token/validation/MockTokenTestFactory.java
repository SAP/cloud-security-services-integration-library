package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import org.mockito.Mockito;

import java.time.Instant;

import static org.mockito.Mockito.when;

public class MockTokenTestFactory {

	private final Token token = Mockito.mock(Token.class);

	public MockTokenTestFactory withExpiration(Instant expirationDate) {
		when(token.getExpiration()).thenReturn(expirationDate);
		return this;
	}
	public MockTokenTestFactory withNotBefore(Instant notBeforeDate) {
		when(token.getNotBefore()).thenReturn(notBeforeDate);
		return this;
	}

	public Token build() {
		return token;
	}
}
