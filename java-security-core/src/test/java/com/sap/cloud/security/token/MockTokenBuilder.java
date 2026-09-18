/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import org.mockito.Mockito;

import java.time.Instant;
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

	public AbstractToken build() {
		return token;
	}
}
