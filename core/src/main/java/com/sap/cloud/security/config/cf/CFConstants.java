package com.sap.cloud.security.config.cf;

public class CFConstants {

	public static final String CREDENTIALS = "credentials";

	// XSUAA ähnlich TokenClaims
	public static final String URL = "url";
	public static final String CLIENT_ID = "clientid";
	public static final String CLIENT_SECRET = "clientsecret";
	public static final String UAA_DOMAIN = "uaadomain"; // XSUAA und IAS
	public static final String SERVICE_PLAN = "plan";

	public enum ServiceType { // TODO ServiceName - überall
		XSUAA, IAS; // configurable with key
		String propertyName() {
			return toString().toLowerCase();
		}
	}

	public enum Plan { // is service instance specific -> hide
		BROKER, APPLICATION;

		public static Plan from(String planAsString) {
			return Plan.valueOf(planAsString.toUpperCase());
		}
	}
}
