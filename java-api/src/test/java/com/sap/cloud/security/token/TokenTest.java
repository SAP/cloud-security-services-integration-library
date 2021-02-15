package com.sap.cloud.security.token;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class TokenTest {

	@Test
	public void create() {
		Token cut = Token.create("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assertNotNull(cut);

		cut = Token.create("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assertNotNull(cut);
	}
}
