package com.sap.cloud.security.config;

/**
 * Represents a supported identity service.
 */
public enum Service {
	XSUAA("xsuaa"), IAS(getIasServiceName());

	private static String getIasServiceName() {
		return System.getenv("IAS_SERVICE_NAME"); // TODO as of now its "identity-beta"
	}

	private final String cloudFoundryName;

	Service(String cloudFoundryName) {
		this.cloudFoundryName = cloudFoundryName;
	}

	/**
	 * Returns the name of the identity service as it appears on Cloud Foundry
	 * marketplace.
	 * 
	 * @return name of the identity service in context of Cloud Foundry environment.
	 */
	public String getCFName() {
		if(this == IAS && cloudFoundryName == null) {
			throw new UnsupportedOperationException("IAS Service is not yet supported.");
		}
		return cloudFoundryName;
	}
}
