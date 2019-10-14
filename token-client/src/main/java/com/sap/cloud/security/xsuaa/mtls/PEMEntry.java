package com.sap.cloud.security.xsuaa.mtls;

class PEMEntry {
	private final String type;
	private final byte[] data;

	public PEMEntry(String type, byte[] data) {
		this.type = type;
		this.data = data;
	}

	public String getType() {
		return type;
	}

	public byte[] getData() {
		return data; // NOSONAR
	}
}
