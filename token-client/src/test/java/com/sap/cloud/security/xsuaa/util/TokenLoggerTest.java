package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;

import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class TokenLoggerTest {

	private static final String JKU_HEADER = "http://my.jku/token_keys";
	private static final String CLIENT_ID = "clientId123";
	private static final String[] SCOPES = { "scope1", "scope2" };

	private final static String TOKEN = new JwtGenerator(CLIENT_ID)
			.addScopes(SCOPES)
			.setJku(JKU_HEADER)
			.getToken().getTokenValue();
	private static final DecodedJwt DECODED_JWT = Base64JwtDecoder.getInstance().decode(TOKEN);

	private TokenLogger cut;
	private Logger loggerMock;

	@Before
	public void setUp() {
		loggerMock = mock(Logger.class);
		when(loggerMock.isDebugEnabled()).thenReturn(true);
		cut = TokenLogger.getInstance(loggerMock);
	}

	@Test
	public void convertToReadableFormat_displaysRelevantData() {
		String logEntry = TokenLogger.convertToReadableFormat(TOKEN);
		assertThat(logEntry)
				.contains("Jwt header")
				.contains(JKU_HEADER)
				.contains("Jwt payload")
				.contains(CLIENT_ID)
				.contains(SCOPES);
	}

	@Test
	public void convertToReadableFormat_doesNotContainSignatureNorEncodedToken() {
		String logEntry = TokenLogger.convertToReadableFormat(TOKEN);
		assertThat(logEntry)
				.doesNotContain(DECODED_JWT.getSignature())
				.doesNotContain(TOKEN);
	}

	@Test
	public void convertToReadableFormat_inputIsNotAToken_returnsEmptyString() {
		assertThat(TokenLogger.convertToReadableFormat("")).isEmpty();
		assertThat(TokenLogger.convertToReadableFormat("not.a.token")).isEmpty();
		assertThat(TokenLogger.convertToReadableFormat(null)).isEmpty();
	}

	@Test
	public void logToken_containsDescriptionAndConvertedToken() {
		ArgumentCaptor<String> debugLogCaptor = ArgumentCaptor.forClass(String.class);
		cut.logToken(TOKEN, "useful description");

		verify(loggerMock, times(2)).debug(debugLogCaptor.capture());

		assertThat(debugLogCaptor.getAllValues())
				.containsExactly("useful description", TokenLogger.convertToReadableFormat(TOKEN));
	}
	@Test
	public void logToken_descriptionIsNull_logsTokenOnly() {
		ArgumentCaptor<String> debugLogCaptor = ArgumentCaptor.forClass(String.class);
		cut.logToken(TOKEN, null);

		verify(loggerMock, times(1)).debug(debugLogCaptor.capture());
		assertThat(debugLogCaptor.getValue()).isEqualTo(TokenLogger.convertToReadableFormat(TOKEN));
	}

	@Test
	public void logToken_doesNotLogSignatureNorEncodedToken() {
		ArgumentCaptor<String> debugLogCaptor = ArgumentCaptor.forClass(String.class);
		cut.logToken(TOKEN, "");

		verify(loggerMock, times(2)).debug(debugLogCaptor.capture());

		String logs = debugLogCaptor.getAllValues().stream().collect(Collectors.joining(" "));

		assertThat(logs)
				.doesNotContain(TOKEN)
				.doesNotContain(DECODED_JWT.getSignature());
	}

	@Test
	public void logToken_tokenIsNotDecodable_doesNotLog() {
		cut.logToken("not.a.token", "useful description");

		verify(loggerMock, times(1)).isDebugEnabled();
		verifyNoMoreInteractions(loggerMock);
	}
}