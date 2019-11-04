package com.sap.cloud.security.json;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Utility class to hide the interaction with the JSON library.
 */
public class JSONParser {

	private final String jsonString;
	private JSONObject jsonObject;

	public JSONParser(String jsonString) {
		this.jsonString = jsonString;
	}

	/**
	 * Parses the json object for the given {@code keyName} and returns a list of type {@link T}.
	 *
	 * @param keyName the key inside the json structure which contains a list as values of type {@link T}.
	 * @param type    type parameter for generic type {@link T}.
	 * @return the list of type {@link T} or null if the key does not exist.
	 * @throws JSONParsingException if the json object with the given key is
	 *                              not a list or list elements are not of type {@link T}.
	 */
	public <T> List<T> getValueAsList(String keyName, Class<T> type) {
		return getJSONArray(keyName).map(jsonArray -> convertToList(jsonArray, type)).orElse(null);
	}

	/**
	 * Parses the json object for the given {@code keyName} and returns the json object
	 * identified by {@code keyName} as a map.
	 * @param keyName the key inside the json structure which contains an json object.
	 * @return the json object identified by {@code keyName} as a map.
	 */
	public Map<String, Object> getValueAsMap(String keyName) {
		try {
			return getJsonObject(keyName).map(JSONObject::toMap).orElse(null);
		} catch (JSONException e) {
			throw new JSONParsingException(e.getMessage());
		}
	}

	/**
	 * Returns the json string object idendified by the given {@code keyName}.
	 *
	 * @param keyName the name of the key.
	 * @return the json string object.
	 * @throws JSONParsingException if the json object identified by the given key is not a string.
	 */
	public String getValueAsString(String keyName) {
		if (contains(keyName)) {
			try {
				return getJsonObject().getString(keyName);
			} catch (JSONException e) {
				throw new JSONParsingException(e.getMessage());
			}
		}
		return null;
	}

	/**
	 * @param key the name of the key.
	 * @return true if the json object contains the key.
	 */
	public boolean contains(String key) {
		return getJsonObject().has(key);
	}

	private <T> List<T> convertToList(JSONArray jsonArray, Class<T> type) {
		List<T> valuesAsList = new ArrayList<>(jsonArray.length());
		for (int i = 0; i < jsonArray.length(); i++) {
			Object value = jsonArray.get(i);
			try {
				valuesAsList.add(type.cast(value));
			} catch (ClassCastException e) {
				throw new JSONParsingException(e.getMessage());
			}
		}
		return valuesAsList;
	}

	private Optional<JSONObject> getJsonObject(String keyName) {
		JSONObject jsonObject = getJsonObject();
		return Optional.ofNullable(jsonObject.optJSONObject(keyName));
	}

	private Optional<JSONArray> getJSONArray(String keyName) {
		if (contains(keyName)) {
			try {
				return Optional.ofNullable(getJsonObject().getJSONArray(keyName));
			} catch (JSONException e) {
				throw new JSONParsingException(e.getMessage());
			}
		}
		return Optional.empty();
	}

	private JSONObject getJsonObject() {
		if (jsonObject == null) {
			jsonObject = new JSONObject(jsonString);
		}
		return jsonObject;
	}
}
