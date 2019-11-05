package com.sap.cloud.security.json;

import java.time.Instant;
import java.util.List;

/**
 * Interface used to expose JSON data.
 */
public interface JsonObject {

	/**
	 * Parses the json object for the given property {@code name} and returns a list
	 * of type {@link T}. If the property with the given name is not found, null is
	 * returned.
	 * 
	 * @param name
	 *            the property inside the json structure which contains a list as
	 *            values of type {@link T}.
	 * @param type
	 *            type parameter for generic type {@link T}.
	 * @return the list of type {@link T} or null if the property does not exist.
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
	Instant getAsInstant(String name);

	/**
	 * @param name
	 *            the name of the property.
	 * @return true if the json object contains the given property.
	 */
	boolean contains(String name);
}
