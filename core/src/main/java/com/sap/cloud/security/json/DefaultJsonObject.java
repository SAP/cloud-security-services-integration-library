package com.sap.cloud.security.json;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.annotation.Nullable;
import java.time.DateTimeException;
import java.time.Instant;
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
	public boolean contains(String key) {
		return getJsonObject().has(key);
	}

	@Override
	@Nullable
	public <T> List<T> getAsList(String name, Class<T> type) {
		return getJSONArray(name).map(jsonArray -> castToListOfType(jsonArray, type)).orElse(null);
	}

	@Override
	@Nullable
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
	@Nullable
	public Instant getAsInstant(String name) {
		if (contains(name)) {
			return getLong(name)
					.map(this::convertToInstant)
					.orElse(null);
		}
		return null;
	}

	@Override
	@Nullable
	public JsonObject getJsonObject(String keyName) {
		if (contains(keyName)) {
			JSONObject newJsonObject;
			try {
				newJsonObject = getJsonObject().getJSONObject(keyName);
			} catch (JSONException e) {
				throw new JsonParsingException(e.getMessage());
			}
			return Optional.ofNullable(newJsonObject)
					.map(Object::toString)
					.map(DefaultJsonObject::new)
					.orElse(null);
		}
		return null;
	}

	@Override
	@Nullable
	public List<JsonObject> getJsonObjects(String keyName) {
		return getJSONArray(keyName)
				.map(this::convertToJsonObjects)
				.orElse(null); //TODO return Empty list
	}

	private List<JsonObject> convertToJsonObjects(JSONArray jsonArray) {
		List<JsonObject> jsonObjects = new ArrayList<>();
		jsonArray.forEach(jsonArrayObject -> {
			if (jsonArrayObject instanceof JSONObject) {
				jsonObjects.add(new DefaultJsonObject(jsonArrayObject.toString()));
			} else {
				throw new JsonParsingException("Array does not only contain json objects!");
			}
		});
		return jsonObjects;
	}

	private Optional<Long> getLong(String name) {
		try {
			return Optional.ofNullable(getJsonObject().getLong(name));
		} catch (JSONException e) {
			throw new JsonParsingException(e.getMessage());
		}
	}

	private Instant convertToInstant(long epochSeconds) {
		try {
			return Instant.ofEpochSecond(epochSeconds);
		} catch (DateTimeException | NumberFormatException e) {
			throw new JsonParsingException(e.getMessage());
		}
	}

	private <T> List<T> castToListOfType(JSONArray jsonArray, Class<T> type) {
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
			try {
				jsonObject = new JSONObject(jsonString);
			} catch (JSONException e) {
				throw new JsonParsingException(e.getMessage());
			}
		}
		return jsonObject;
	}
}
