package com.sap.cloud.security.config;

public enum Service {
	XSUAA("xsuaa"), IAS("iasb");

	private final String cfName;

	Service(String cfName) {
		this.cfName = cfName;
	}

	public String getCFName() {
		return cfName;
	}
}
