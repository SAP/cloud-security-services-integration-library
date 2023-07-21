/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.json;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.*;

/**
 * Use this class to parse a Json String. This might be relevant in case the
 * {@link com.sap.cloud.security.config.OAuth2ServiceConfiguration} does not
 * provide all required properties.
 */
public class DefaultJsonObject implements JsonObject {

	private static final long serialVersionUID = 2204172045251807L;

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultJsonObject.class);

	private final transient JSONObject jsonObject;

	/**
	 * Create an instance
	 *
	 * @param jsonString
	 *            the content in json format that should be parsed.
	 */
	public DefaultJsonObject(String jsonString) {
		this.jsonObject = createJsonObject(jsonString);
	}

	@Override
	public boolean contains(String key) {
		return getJsonObject().has(key);
	}

	@Override
	public boolean isEmpty() {
		return getJsonObject().isEmpty();
	}

	@Override
	public <T> List<T> getAsList(String name, Class<T> type) {
		return getJSONArray(name).map(jsonArray -> castToListOfType(jsonArray, type)).orElse(Collections.emptyList());
	}

	@Override
	public List<String> getAsStringList(String name) {
		List<String> list = new ArrayList<>();
		if (contains(name)) {
			if (getJsonObject().get(name) instanceof String) {
				list.add(getAsString(name));
			} else {
				list = getAsList(name, String.class);
			}
		}
		return list;
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

	@Nullable
	@Override
	public Long getAsLong(String name) {
		if (contains(name)) {
			return getLong(name).orElse(null);
		}
		return null;
	}

	@Override
	@Nullable
	public JsonObject getJsonObject(String name) {
		if (contains(name)) {
			JSONObject newJsonObject;
			try {
				newJsonObject = getJsonObject().getJSONObject(name);
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
	public List<JsonObject> getJsonObjects(String name) {
		return getJSONArray(name)
				.map(this::convertToJsonObjects)
				.orElse(new ArrayList<>());
	}

	@Override
	public Map<String, String> getKeyValueMap() {
		Map<String, String> map = new HashMap<>();
		Iterator<String> keysItr = getJsonObject().keys();
		while (keysItr.hasNext()) {
			String key = keysItr.next();
			Object value = jsonObject.get(key);
			if (value instanceof String) {
				map.put(key, String.valueOf(value));
			}
		}
		return map;
	}

	@Override
	public String asJsonString() {
		return jsonObject.toString();
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

	private Optional<JSONArray> getJSONArray(String name) {
		if (contains(name)) {
			try {
				return Optional.ofNullable(getJsonObject().getJSONArray(name));
			} catch (JSONException e) {
				throw new JsonParsingException(e.getMessage());
			}
		}
		return Optional.empty();
	}

	private JSONObject getJsonObject() {
		return jsonObject;
	}

	@SuppressWarnings("squid:S2139")
	private JSONObject createJsonObject(String jsonString) {
		try {
			return new JSONObject(jsonString);
		} catch (JSONException e) {
			LOGGER.error("Given json string '{}' is not valid, error message: {}", jsonString, e.getMessage());
			throw new JsonParsingException(e.getMessage());
		}
	}

	@Override
	public String toString() {
		return jsonObject.toString(2);
	}
}
