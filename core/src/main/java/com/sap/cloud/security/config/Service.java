package com.sap.cloud.security.config;

public enum Service {
	XSUAA("xsuaa"), IAS("iasb");

	private final String name;

	Service(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
}
