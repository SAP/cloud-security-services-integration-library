package com.sap.cloud.security.json;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class DefaultJsonObject implements JsonObject {

	private final String jsonString;
	private JSONObject jsonObject;

	public DefaultJsonObject(String jsonString) {
		this.jsonString = jsonString;
	}

	@Override
	public <T> List<T> getAsList(String name, Class<T> type) {
		return getJSONArray(name).map(jsonArray -> convertToList(jsonArray, type)).orElse(null);
	}

	@Override
	public String getAsString(String name) {
		if (contains(name)) {
			try {
				return getJsonObject().getString(name);
			} catch (JSONException e) {
				throw new JsonParsingException(e.getMessage());
			}
		}
		return null;
	}

	@Override
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
				throw new JsonParsingException(e.getMessage());
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
				throw new JsonParsingException(e.getMessage());
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
