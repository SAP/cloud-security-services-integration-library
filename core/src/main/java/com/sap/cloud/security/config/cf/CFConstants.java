package com.sap.cloud.security.config.cf;

public class CFConstants {

	public static final String CREDENTIALS = "credentials";
	public static final String URL = "url";
	public static final String CLIENT_ID = "clientid";
	public static final String UAA_DOMAIN = "uaadomain";
	public static final String CLIENT_SECRET = "clientsecret";
	public static final String SERVICE_PLAN = "plan";

	public enum ServiceType {
		XSUAA, IAS;
		String propertyName() {
			return toString().toLowerCase();
		}
	}

	public enum Plan {
		BROKER, APPLICATION;

		public static Plan from(String planAsString) {
			return Plan.valueOf(planAsString.toUpperCase());
		}
	}
}
