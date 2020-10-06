package com.sap.cloud.security.test;

// TODO api ServiceMockConfiguration
public interface SecurityTestBuilder {

	/**
	 * Overwrites the port on which the identity service mock server runs
	 * (WireMock). It needs to be configured before the test execution has started.
	 * If the port is not specified or is set to 0, a free random port is chosen.
	 *
	 * @param port
	 *            the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	SecurityTestBuilder setPort(int port);

	/**
	 * Overwrites the private/public key pair to be used. The private key is used to
	 * sign the jwt token. The public key is provided by jwks endpoint (on behalf of
	 * WireMock). Checked exceptions are caught and rethrown as runtime exceptions
	 * for test convenience.
	 *
	 * @param publicKeyPath
	 *            resource path to public key file.
	 * @param privateKeyPath
	 *            resource path to private key file.
	 * @return the rule itself.
	 */
	SecurityTestBuilder setKeys(String publicKeyPath, String privateKeyPath);
}
