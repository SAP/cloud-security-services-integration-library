package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.Arrays;

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

	public MockTokenTestFactory withScopes(String...scopes) {
		when(token.getScopes()).thenReturn(Arrays.asList(scopes));
		return this;
	}

	public MockTokenTestFactory withClientId(String clientId) {
		when(token.getClaimAsString(TokenClaims.CLAIM_CLIENT_ID)).thenReturn(clientId);
		return this;
	}

	public Token build() {
		return token;
	}
}
