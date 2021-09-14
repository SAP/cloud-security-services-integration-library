package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;

public class DefaultEnvironmentLoader implements EnvironmentLoader {
	private static final Environment cfEnvironment = CFEnvironment.getInstance(); // singleton

	@Override
	public Environment getCurrent() {
		return cfEnvironment;
	}
}
