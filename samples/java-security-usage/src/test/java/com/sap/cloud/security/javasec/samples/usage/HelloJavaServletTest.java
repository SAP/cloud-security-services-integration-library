package com.sap.cloud.security.javasec.samples.usage;

import org.junit.Ignore;
import org.junit.Test;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;

//@TestServletSecurity
public class HelloJavaServletTest {

	@Test
	@Ignore
	public void doGet() {
		//Token dummyToken = null;// = MockXsuaaTokenBuilder.setClientId().setApplicationId().setScopes()... see JwtGenerator
		//SecurityContext.setToken(dummyToken);

		//HelloJavaServlet cut = new HelloJavaServlet();
		//cut.doGet();
	}

	@Test
	@Ignore
	public void doGetIT() {
		//similar to WEB MVC Test that executes the Servlet Filter chain
		//MockTokenKeyService.getPublicKey -->
		//TokenKeyServiceWithCache.getPubliKey -> PublicKey which fits to the private key, the dummyToken was signed with

		// How to inject to ServletFilter
	}
}