package com.sap.cloud.security.json;

import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class DefaultJsonObjectTest {

	public static final Instant FIRST_OF_APRIL = LocalDate.of(2019, 4, 1).atStartOfDay().toInstant(ZoneOffset.UTC);

	public static final String KEY_1 = "key-1";
	public static final String KEY_2 = "key-2";

	public static final String STRING_VALUE = "\"string text\"";
	public static final String STRING_LIST_VALUE = "[\"a\", \"b\", \"c\"]";

	private DefaultJsonObject cut;

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
		assertThat(cut.getAsString(KEY_1)).isEqualTo(STRING_VALUE.substring(1, STRING_VALUE.length() - 1));
	}

	@Test
	public void getValueAsString_keyDoesNotExists_returnsNull() {
		assertThat(cut.getAsString("keyDoesNotExist")).isNull();
	}

	@Test
	public void getValueAsString_keyDoesExistButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getAsString(KEY_2)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getValueOAsListOfStrings_keyExists_returnsList() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		List<String> list = cut.getAsList(KEY_2, String.class);

		assertThat(list).hasSize(3);
		assertThat(list).first().isEqualTo("a");
	}

	@Test
	public void getValueOAsListOfStrings_keyDoesNotExist_returnsNull() {
		assertThat(cut.getAsList("keyDoesNotExist", String.class)).isNull();
	}

	@Test
	public void getValueOAsListOfStrings_keyExistsButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getAsList(KEY_2, Integer.class)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getInstant_propertyExistsAndIsEpochTime_returnsInstant() {
		cut = createJsonParser(KEY_1, String.valueOf(FIRST_OF_APRIL.getEpochSecond()));

		Instant instant = cut.getAsInstant(KEY_1);

		assertThat(instant).isEqualTo(Instant.from(FIRST_OF_APRIL));
	}

	@Test
	public void getInstant_propertyDoesNotExist_returnsNull() {
		assertThat(cut.getAsInstant("keyDoesNotExist")).isNull();
	}

	@Test
	public void getInstant_propertyExistsButIsNotInEpochTime_throwsException() {
		assertThatThrownBy(() -> cut.getAsInstant(KEY_1))
				.isInstanceOf(JsonParsingException.class);
	}

	private DefaultJsonObject createJsonParser(String key, String value) {
		String jsonString = createJsonObjectString(key, value);
		return new DefaultJsonObject(jsonString);
	}

	private String createJsonObjectString(String key, String value) {
		return String.format("{%s : %s}", key, value);
	}
}