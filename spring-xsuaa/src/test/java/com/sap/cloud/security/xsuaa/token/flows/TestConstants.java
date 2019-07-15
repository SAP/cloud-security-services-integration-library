package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;

//@formatter:off
interface TestConstants {
    String clientId          = "sb-spring-netflix-demo!t12291";
    String clientSecret      = "2Tc2Xz7DNy4KiACwvunulmxF32w=";
    URI xsuaaBaseUri         = URI.create("https://d056076-sub1.authentication.eu10.hana.ondemand.com/");
    URI tokenEndpointUri     = URI.create("https://d056076-sub1.authentication.eu10.hana.ondemand.com/oauth/token");
    URI authorizeEndpointUri = URI.create("https://d056076-sub1.authentication.eu10.hana.ondemand.com/oauth/authorize");
    URI keySetEndpointUri    = URI.create("https://d056076-sub1.authentication.eu10.hana.ondemand.com/token_keys");
}
//@formatter:on