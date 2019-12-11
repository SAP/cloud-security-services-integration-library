package com.sap.cloud.security.token;

import org.mockito.Mockito;

import java.time.Instant;
import java.util.Arrays;
import java.util.GregorianCalendar;

import static org.mockito.Mockito.when;

public class MockTokenBuilder {
	public static final Instant NO_EXPIRE_DATE = new GregorianCalendar(2190, 11, 31).getTime().toInstant();

	private final AbstractToken token = Mockito.mock(AbstractToken.class);

	public MockTokenBuilder withExpiration(Instant expirationDate) {
		when(token.getExpiration()).thenReturn(expirationDate);
		return this;
	}

	public MockTokenBuilder withNotBefore(Instant notBeforeDate) {
		when(token.getNotBefore()).thenReturn(notBeforeDate);
		return this;
	}

	public MockTokenBuilder withClientId(String clientId) {
		when(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).thenReturn(clientId);
		return this;
	}

	// TODO XSUAA specifc
	public MockTokenBuilder withScopes(String... scopes) {
		when(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).thenReturn(Arrays.asList(scopes));
		return this;
	}

	public AbstractToken build() {
		return token;
	}
}
