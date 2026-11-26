package com.sap.cloud.security.token.validation;

/**
 * Legacy internal extension for test credentials with uaadomain 'localhost'.
 *
 * @deprecated XSUAA validation no longer discovers or invokes implementations. Configure the complete mock-server
 *             base URL, including its port, as uaadomain instead.
 */
@Deprecated
public interface XsuaaJkuFactory {
	String create(String token);
}
