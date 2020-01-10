package com.sap.cloud.security.json;

/**
 * An extraordinary runtime exception during json parsing.
 */
public class JsonParsingException extends RuntimeException {

	public JsonParsingException(String message) {
		super(message);
	}
}
