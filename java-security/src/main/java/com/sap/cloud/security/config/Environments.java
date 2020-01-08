package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;

public class Environments {

	private static final Environment cfEnvironment = CFEnvironment.getInstance(); // singleton

	private Environments() {
		// use factoryMethods instead
	}

	public static Environment getCurrent() {
		// TODO Kubernetes: probe in which environemt it runs currently: CF or Kubernetes, e.g.
		// if(System.getenv("VCAP_SERVICES") != null) {
		return cfEnvironment;
	}

}
