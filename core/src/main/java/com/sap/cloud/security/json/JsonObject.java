package com.sap.cloud.security.json;

import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;

/**
 * Interface used to expose JSON data.
 */
public interface JsonObject {

	/**
	 * @param name
	 *            the name of the property.
	 * @return true if the json object contains the given property.
	 */
	boolean contains(String name);

	/**
	 * Parses the json object for the given property {@code name} and returns a list
	 * of type {@link T}. If the property with the given name is not found, an empyt
	 * list is returned.
	 *
	 * @param name
	 *            the property inside the json structure which contains a list as
	 *            values of type {@link T}.
	 * @param type
	 *            type parameter for generic type {@link T}.
	 * @return the list of type {@link T}.
	 * @throws JsonParsingException
	 *             if the json object with the given key is not a list or list
	 *             elements are not of type {@link T}.
	 */
	<T> List<T> getAsList(String name, Class<T> type);

	/**
	 * Returns the string identified by the given property {@code name}. If the
	 * property with the given name is not found, null is returned.
	 *
	 * @param name
	 *            the name of the property.
	 * @return the json string object.
	 * @throws JsonParsingException
	 *             if the json object identified by the given property is not a
	 *             string.
	 */
	@Nullable
	String getAsString(String name);

	/**
	 * Returns an {@link Instant} identified by the given property {@code name}. If
	 * the property with the given name is not found, null is returned.
	 *
	 * @param name
	 *            the name of the property.
	 * @return the {@link Instant} object.
	 * @throws JsonParsingException
	 *             if the json object identified by the given property does not
	 *             represent a date in unix time.
	 */
	@Nullable
	Instant getAsInstant(String name);

	/**
	 * Returns a nested JSON object as @{link JsonObject} instance.
	 * 
	 * @param name
	 *            the name of property.
	 * @return the {@link JsonObject}.
	 * @throws JsonParsingException
	 *             if the json object identified by the given property is not a JSON
	 *             object structure.
	 */
	@Nullable
	JsonObject getJsonObject(String name);

	/**
	 * Returns a nested array of JSON objects as list of @{link JsonObject}
	 * instances. If the property with the given name is not found, an empty
	 * list is returned.
	 * 
	 * @param name
	 *            the name of property.
	 * @return a list of {@link JsonObject} instances.
	 * @throws JsonParsingException
	 *             if the json object identified by the given property is not an
	 *             array of JSON objects.
	 */
	List<JsonObject> getJsonObjects(String name);
}
