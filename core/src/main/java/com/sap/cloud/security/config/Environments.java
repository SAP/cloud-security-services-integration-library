package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;

public class Environments {

	private static final Environment cfEnvironment = new CFEnvironment();

	public static Environment getCurrentEnvironment() {
		return cfEnvironment; // TODO implement support for other environments
	}

}
