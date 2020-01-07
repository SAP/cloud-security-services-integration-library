package com.sap.cloud.security.samples;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(HelloJavaServlet.ENDPOINT)
@ServletSecurity(@HttpConstraint(rolesAllowed = { "Read" }))
public class HelloJavaServlet extends HttpServlet {
	static final String ENDPOINT = "/hello-java-security";
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(HelloJavaServlet.class);

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
		response.setContentType("text/plain");
		Token token = SecurityContext.getToken();
		try {
			StringBuilder message = new StringBuilder();
			message.append("You ('");
			message.append(token.getClaimAsString(TokenClaims.XSUAA.EMAIL));
			message.append("') can access the application with the following scopes: '");
			message.append(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES));
			message.append("'.");
			response.getWriter().write(message.toString());
			response.setStatus(HttpServletResponse.SC_OK);
		} catch (final IOException e) {
			logger.error("Failed to write error response: {}.", e.getMessage(), e);
		}
	}

}
