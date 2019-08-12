package com.sap.cloud.security.xsuaa.client;

import org.junit.Before;
import org.junit.Test;

import java.util.Date;
import static org.hamcrest.CoreMatchers.is;

import static org.junit.Assert.assertThat;

public class OAuth2AccessTokenTest {

	@Before
	public void setup() {
	}

	@Test
	public void getExpiredDateFromAccessToken() {
		Date mockDate = new Date(1565047106752L);
		OAuth2AccessToken accessToken = new OAuth2AccessTokenMock("e9511922b5e64c49ba0eedcc8d772e76", 43199, mockDate);
		assertThat(accessToken.getExpiredAtDate().getTime(), is(1565090305752L));
	}

	// for testing only
	Date getCurrentTime() {
		return new Date();
	}

	private static class OAuth2AccessTokenMock extends OAuth2AccessToken {

		private Date mockDate;

		public OAuth2AccessTokenMock(String accessToken, long expiredInSeconds, Date mockDate) {
			super(accessToken, expiredInSeconds);
			this.mockDate = mockDate;
		}

		Date getCurrentTime() {
			return mockDate;
		}
	}
}
