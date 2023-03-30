/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.json;

import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

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
	 * Method to check if the underlying json object is empty.
	 *
	 * @return true if the jsonObject is empty.
	 */
	boolean isEmpty();

	/**
	 * Parses the json object for the given property {@code name} and returns a list
	 * of type {@link T}. If the property with the given name is not found, an empty
	 * list is returned.
	 *
	 * @param <T>
	 *            the type of the list elements.
	 * @param name
	 *            the property inside this json object which contains a list as
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
	 * Parses the json object for the given property {@code name} and returns a
	 * String list. If the property with the given name is not found, an empty list
	 * is returned.
	 *
	 * For example {@code "aud" : "single-value"} or
	 * {@code "aud" : ["value-1", "value-2"]}
	 *
	 * @param name
	 *            the property inside this json object which contains a String list.
	 * @return the String list.
	 * @throws JsonParsingException
	 *             if the json object with the given key is not a String array or of
	 *             type String.
	 * @see #getAsString
	 */
	List<String> getAsStringList(String name);

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
	 * Returns a {@link Long} identified by the given property {@code name}. If the
	 * property with the given name is not found, null is returned.
	 *
	 * @param name
	 *            the name of property.
	 * @return the {@link Long} object.
	 * @throws JsonParsingException
	 *             if the json object identified by the given property does not
	 *             represent a long value
	 */
	@Nullable
	Long getAsLong(String name);

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
	 * Returns a nested array of JSON objects as list of {@link JsonObject}
	 * instances. If the property with the given name is not found, an empty list is
	 * returned.
	 * 
	 * @param name
	 *            the name of property.
	 * @return a list of {@link JsonObject} instances.
	 * @throws JsonParsingException
	 *             if the json object identified by the given property is not an
	 *             array of JSON objects.
	 */
	List<JsonObject> getJsonObjects(String name);

	/**
	 * Returns a key-value map of the JSON properties.
	 *
	 * Example:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	String vcapServices = System.getenv(CFConstants.VCAP_SERVICES);
	 * 	JsonObject serviceJsonObject = new DefaultJsonObject(vcapServices).getJsonObjects(Service.XSUAA.getCFName())
	 * 			.get(0);
	 * 	Map&lt;String, String&gt; xsuaaConfigMap = serviceJsonObject.getKeyValueMap();
	 * 	Map&lt;String, String&gt; credentialsMap = serviceJsonObject.getJsonObject(CFConstants.CREDENTIALS)
	 * 			.getKeyValueMap();
	 * }
	 * </pre>
	 * 
	 * @return the json properties as key-value map
	 */
	Map<String, String> getKeyValueMap();

	/**
	 * Returns the json object as a json string.
	 * 
	 * @return the json object in string representation.
	 */
	String asJsonString();
}
