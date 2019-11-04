package com.sap.cloud.security.json;

import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class JSONParserTest {

	public static final String KEY_1 = "key-1";
	public static final String KEY_2 = "key-2";

	public static final String STRING_VALUE = "\"string text\"";
	public static final String STRING_LIST_VALUE = "[\"a\", \"b\", \"c\"]";

	private JSONParser cut;

	@Before
	public void setUp() {
		cut = createJsonParser(KEY_1, STRING_VALUE);
	}


	@Test
	public void contains_keyDoesExist_isTrue() {
		assertThat(cut.contains(KEY_1)).isTrue();
	}

	@Test
	public void contains_keyDoesNotExist_isFalse() {
		assertThat(cut.contains("doesNotExist")).isFalse();
	}

	@Test
	public void getValueAsString_keyExists_returnsStringValue() {
		assertThat(cut.getValueAsString(KEY_1)).isEqualTo(STRING_VALUE.substring(1, STRING_VALUE.length() - 1));
	}

	@Test
	public void getValueAsString_keyDoesNotExists_returnsNull() {
		assertThat(cut.getValueAsString("keyDoesNotExist")).isNull();
	}

	@Test
	public void getValueAsString_keyDoesExistButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getValueAsString(KEY_2)).isInstanceOf(JSONParsingException.class);
	}

	@Test
	public void getValueOAsListOfStrings_keyExists_returnsList() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		List<String> list = cut.getValueAsList(KEY_2, String.class);

		assertThat(list).hasSize(3);
		assertThat(list).first().isEqualTo("a");
	}

	@Test
	public void getValueOAsListOfStrings_keyDoesNotExist_returnsNull() {
		assertThat(cut.getValueAsList("keyDoesNotExist", String.class)).isNull();
	}

	@Test
	public void getValueOAsListOfStrings_keyExistsButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getValueAsList(KEY_2, Integer.class)).isInstanceOf(JSONParsingException.class);
	}

	@Test
	public void getValueAsMap_keyExists_returnsStringObjectMap() {
		String mapValue = "mapStringValue";
		cut = createJsonParser(KEY_1, createJsonObjectString(KEY_2, mapValue));

		Map<String, Object> valueAsMap = cut.getValueAsMap(KEY_1);

		assertThat(valueAsMap).hasSize(1);
		assertThat(valueAsMap).containsOnlyKeys(KEY_2);
		assertThat(valueAsMap).containsValue(mapValue);

	}

	@Test
	public void getValueAsMap_keyDoesNotExist_returnsNull() {
		assertThat(cut.getValueAsMap("keyDoesNotExist")).isNull();
	}

	private JSONParser createJsonParser(String key, String value) {
		String jsonString = createJsonObjectString(key, value);
		return new JSONParser(jsonString);
	}

	private String createJsonObjectString(String key, String value) {
		return String.format("{%s : %s}", key, value);
	}
}