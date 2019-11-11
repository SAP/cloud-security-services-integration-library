package com.sap.cloud.security.config.cf;

public enum CFService {
	XSUAA("xsuaa"), IAS("iasb");

	private final String name;

	CFService(String name) {
		this.name = name;
	}

	String getName() {
		return name;
	}
}
