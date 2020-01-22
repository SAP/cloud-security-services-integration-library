package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;

/**
 * Central entry point to access the current SAP Cloud Platform
 * {@link Environment}.
 */
public class Environments {

	private static final Environment cfEnvironment = CFEnvironment.getInstance(); // singleton

	private Environments() {
		// use factoryMethods instead
	}

	/**
	 * Determines the current type of {@link Environment}.
	 * 
	 * @return the current environment
	 */
	public static Environment getCurrent() {
		// TODO Kubernetes: probe in which environemt it runs currently: CF or
		// Kubernetes, e.g.
		// if(System.getenv("VCAP_SERVICES") != null) {
		return cfEnvironment;
	}

}
