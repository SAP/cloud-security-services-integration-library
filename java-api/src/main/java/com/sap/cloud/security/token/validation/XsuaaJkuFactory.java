package com.sap.cloud.security.token.validation;

/**
 * This interface is for INTERNAL usage only to add backward-compatibility for test credentials with uaadomain
 * 'localhost' during JKU construction.
 */
public interface XsuaaJkuFactory {
	String create(String token);
}
