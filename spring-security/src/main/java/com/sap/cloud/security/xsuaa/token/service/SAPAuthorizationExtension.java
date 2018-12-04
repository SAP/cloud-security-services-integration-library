package com.sap.cloud.security.xsuaa.token.service;
import java.io.Serializable;

public class SAPAuthorizationExtension implements Serializable {

	private static final long serialVersionUID = 1L;

	private boolean foreignMode = false;

	public boolean isForeignMode() {
		return foreignMode;
	}

	public void setForeignMode(boolean foreignMode) {
		this.foreignMode = foreignMode;
	}
}