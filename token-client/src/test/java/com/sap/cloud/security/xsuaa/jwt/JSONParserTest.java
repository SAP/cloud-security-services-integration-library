package com.sap.cloud.security.xsuaa.jwt;

import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class JSONParserTest {

	public static final String KEY_1 = "key-1";
	public static final String STRING_VALUE = "\"string text\"";

	public static final String KEY_2 = "key-1";
	public static final String STRING_LIST_VALUE = "[\"a\", \"b\", \"c\"]";

	private JSONParser cut;

	@Before
	public void setUp() throws Exception {
		cut = createJsonParser(KEY_1, STRING_VALUE);
	}

	@Test
	public void getValueOfKey_keyDoesNotExist_isNull() {
		assertThat(cut.getValueOfKey("doesNotExit")).isNull();
	}

	@Test
	public void getValueOfKey_keyDoesExist_isNotNull() {
		assertThat(cut.getValueOfKey(KEY_1)).isNotNull();
	}

	@Test
	public void getStringValueOfKey_keyExists_returnsStringValue() {
		assertThat(cut.getValueAsString(KEY_1)).isEqualTo(STRING_VALUE.substring(1, STRING_VALUE.length() - 1));
	}

	@Test
	public void getValueOfKey_keyExists_returnsList() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		List<?> list = cut.getValueAsList(KEY_2);

		assertThat(list).hasSize(3);
		assertThat(list).first().isInstanceOf(String.class);
		assertThat(list).first().isEqualTo("a");
	}

	private JSONParser createJsonParser(String key, String value) {
		String jsonString = createJsonObjectString(key, value);
		return new JSONParser(jsonString);
	}

	private String createJsonObjectString(String key, String value) {
		return String.format("{%s : %s}", key, value);
	}
}