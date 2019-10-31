package com.sap.cloud.security.xsuaa.jwt;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Utility class to hide the interaction with the JSON library.
 */
class JSONParser {

	private final String jsonString;
	private Map<String, Object> jsonMap;

	JSONParser(String jsonString) {
		this.jsonString = jsonString;
	}

	Object getValueOfKey(String keyName) {
		return getJsonMap().get(keyName);
	}

	List<?> getValueAsList(String keyName) {
		Object value = getJsonMap().get(keyName);
		if (value instanceof List) {
			return (List<?>) value;
		}
		return null;
	}

	String getValueAsString(String keyName) {
		return extractStringOrNull(getJsonMap().get(keyName));
	}

	private Map<String, Object> createMapFromJsonString(String header) {
		try {
			JSONObject jsonObject = new JSONObject(header);
			return jsonObject.toMap();
		} catch (JSONException e) {
			return new HashMap<>();
		}
	}

	private Map<String, Object> getJsonMap() {
		if (jsonMap == null) {
			jsonMap = createMapFromJsonString(jsonString);
		}
		return jsonMap;
	}

	private String extractStringOrNull(Object value) {
		return Optional.ofNullable(value).map(Object::toString).orElse(null);
	}

}
