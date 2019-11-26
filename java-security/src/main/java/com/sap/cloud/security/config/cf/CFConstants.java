package com.sap.cloud.security.config.cf;

public class CFConstants {
	public static final String VCAP_SERVICES = "VCAP_SERVICES";
	public static final String CREDENTIALS = "credentials";
	public static final String SERVICE_PLAN = "plan";
	public static final String URL = "url";

	private CFConstants() {
	}

	public static class XSUAA {
		private XSUAA() {
		}

		public static final String CLIENT_ID = "clientid";
		public static final String CLIENT_SECRET = "clientsecret";
		public static final String UAA_DOMAIN = "uaadomain";
		public static final String APP_ID = "xsappname";
	}

	public static class IAS {
		private IAS() {
		}

		public static final String CLIENT_ID = "username";
		public static final String CLIENT_SECRET = "password";
		public static final String DOMAIN = "domain";
	}

	// TODO move to CFService?
	public enum Plan {
		DEFAULT, BROKER, APPLICATION;

		public static Plan from(String planAsString) {
			return Plan.valueOf(planAsString.toUpperCase());
		}
	}
}
