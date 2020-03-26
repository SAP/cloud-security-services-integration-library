package com.sap.cloud.security.config;

/**
 * Represents a supported identity service.
 */
public enum Service {
	XSUAA("xsuaa"), IAS("identity-beta");

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
		return cloudFoundryName;
	}
}
