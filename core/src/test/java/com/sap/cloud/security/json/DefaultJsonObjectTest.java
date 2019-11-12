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

	private static final Instant FIRST_OF_APRIL = LocalDate.of(2019, 4, 1).atStartOfDay().toInstant(ZoneOffset.UTC);

	private static final String KEY_1 = "key-1";
	private static final String KEY_2 = "key-2";

	private static final String STRING_TEXT = "string text";
	private static final String STRING_VALUE = "\"" + STRING_TEXT + "\"";

	private static final String STRING_LIST_VALUE = "[\"a\", \"b\", \"c\"]";
	private static final String MAP_OBJECT = "{\"key1\": \"value1\",\"key2\": \"value2\"}";

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
	public void getAsString_keyExists_returnsStringValue() {
		assertThat(cut.getAsString(KEY_1)).isEqualTo(STRING_TEXT);
	}

	@Test
	public void getAsString_keyDoesNotExists_returnsNull() {
		assertThat(cut.getAsString("keyDoesNotExist")).isNull();
	}

	@Test
	public void getAsString_keyDoesExistButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getAsString(KEY_2)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getAsListOfStrings_keyExists_returnsList() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		List<String> list = cut.getAsList(KEY_2, String.class);

		assertThat(list).hasSize(3);
		assertThat(list).first().isEqualTo("a");
	}

	@Test
	public void getAsListOfStrings_keyDoesNotExist_returnsEmptyList() {
		assertThat(cut.getAsList("keyDoesNotExist", String.class)).isEmpty();
	}

	@Test
	public void getAsListOfStrings_keyExistsButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getAsList(KEY_2, Integer.class)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getAsInstant_propertyExistsAndIsEpochTime_returnsInstant() {
		cut = createJsonParser(KEY_1, "\"" + FIRST_OF_APRIL.getEpochSecond() + "\"");

		Instant instant = cut.getAsInstant(KEY_1);

		assertThat(instant).isEqualTo(Instant.from(FIRST_OF_APRIL));
	}

	@Test
	public void getAsInstant_propertyExistsAndIsEpochTimeFormattedAsNumber_returnsInstant() {
		cut = createJsonParser(KEY_1, FIRST_OF_APRIL.getEpochSecond());

		Instant instant = cut.getAsInstant(KEY_1);

		assertThat(instant).isEqualTo(Instant.from(FIRST_OF_APRIL));
	}

	@Test
	public void getAsInstant_propertyDoesNotExist_returnsNull() {
		assertThat(cut.getAsInstant("keyDoesNotExist")).isNull();
	}

	@Test
	public void getAsInstant_propertyExistsButIsNotInEpochTime_throwsException() {
		assertThatThrownBy(() -> cut.getAsInstant(KEY_1))
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObject_propertExists_returnsJsonObject() {
		cut = createJsonParser(KEY_1, createJsonObjectString(KEY_1, STRING_VALUE));

		JsonObject jsonObject = cut.getJsonObject(KEY_1);

		assertThat(jsonObject).isNotNull();
		assertThat(jsonObject.getAsString(KEY_1)).isNotNull();
	}

	@Test
	public void getJsonObjects_propertExists_returnsJsonObjects() {
		cut = createJsonParser(KEY_1, "[" + createJsonObjectString(KEY_1, STRING_VALUE) + "]");

		List<JsonObject> jsonObjects = cut.getJsonObjects(KEY_1);

		assertThat(jsonObjects).isNotNull();
		assertThat(jsonObjects).hasSize(1);
		assertThat(jsonObjects.get(0).getAsString(KEY_1)).isNotNull();
	}

	@Test
	public void getJsonObject_propertyDoesNotExists_returnsNull() {
		JsonObject jsonObject = cut.getJsonObject("keyDoesNotExist");

		assertThat(jsonObject).isNull();
	}

	@Test
	public void getJsonObject_propertyExistsButIsNotAnObject_throwsException() {
		assertThatThrownBy(() -> cut.getJsonObject(KEY_1)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObjects_propertyDoesNotExists_returnsEmptyList() {
		List<JsonObject> jsonObjects = cut.getJsonObjects("keyDoesNotExist");

		assertThat(jsonObjects).isEmpty();
	}

	@Test
	public void getJsonObjects_propertyExists_returnsEmptyList() {
		cut = createJsonParser(KEY_1, "[]");

		List<JsonObject> jsonObjects = cut.getJsonObjects(KEY_1);

		assertThat(jsonObjects).isNotNull();
		assertThat(jsonObjects).isEmpty();
	}

	@Test
	public void getJsonObjects_propertyExistsButIsNotAnArray_throwsException() {
		assertThatThrownBy(() -> cut.getJsonObjects(KEY_1)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObjects_malformedJson_throwsException() {
		cut =  new DefaultJsonObject("");

		assertThatThrownBy(() -> cut.getJsonObject(KEY_1)).isInstanceOf(JsonParsingException.class);
	}

	private DefaultJsonObject createJsonParser(String key, Object value) {
		String jsonString = createJsonObjectString(key, value);
		return new DefaultJsonObject(jsonString);
	}

	private String createJsonObjectString(String key, Object value) {
		return String.format("{%s : %s}", key, value);
	}
}