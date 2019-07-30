package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;

//@formatter:off
interface TestConstants {
    String clientId          = "sb-spring-netflix-demo!t12291";
    String clientSecret      = "2Tc2Xz7DNy4KiACwvunulmxF32w=";
    URI xsuaaBaseUri         = URI.create("https://subdomain.authentication.eu10.hana.ondemand.com/");
    URI tokenEndpointUri     = URI.create("https://subdomain.authentication.eu10.hana.ondemand.com/oauth/token");
}
//@formatter:on