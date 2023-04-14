/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.sapbuildpack.xsuaa;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.TokenClaims;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Servlet implementation class HelloTokenServlet
 */
@WebServlet("/hello-token")

// configure servlet to check against scope "$XSAPPNAME.Display"
@ServletSecurity(@HttpConstraint(rolesAllowed = { "Display" }))
public class HelloTokenServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setContentType("text/plain");
		AccessToken accessToken = (AccessToken) request.getUserPrincipal();

		response.getWriter().append("Client ID: ")
				.append("" + accessToken.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID));
		response.getWriter().append("\n");
		response.getWriter().append("Email: ").append("" + accessToken.getClaimAsString(TokenClaims.EMAIL));
		response.getWriter().append("\n");
		response.getWriter().append("Family Name: ").append("" + accessToken.getClaimAsString(TokenClaims.FAMILY_NAME));
		response.getWriter().append("\n");
		response.getWriter().append("First Name: ").append("" + accessToken.getClaimAsString(TokenClaims.GIVEN_NAME));
		response.getWriter().append("\n");
		response.getWriter().append("OAuth Grant Type: ").append("" + accessToken.getGrantType());
		response.getWriter().append("\n");
		response.getWriter().append("OAuth Token: ").append("" + accessToken.getTokenValue());
		response.getWriter().append("\n");

	}

}
