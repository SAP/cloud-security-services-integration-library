package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;

public class Environments {

	private static final Environment cfEnvironment = CFEnvironment.getInstance(); // singleton

	public static Environment getCurrent() {
		// TODO probe in which environemt it runs currently: CF or Kubernetes
		// if(System.getenv("VCAP_SERVICES") != null) {
		return cfEnvironment;
	}

}
