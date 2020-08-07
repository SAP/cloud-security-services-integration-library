package sample.spring.xsuaa;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/hello-servlet")
public class TestServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		resp.getWriter().println("User principal: " + req.getUserPrincipal());
		resp.getWriter().println("remoteUser: " + req.getRemoteUser());

		/**
		 * This will be false because role has no ROLE_ prefix!
		 */
		boolean isUserInRoleDisplay = req.isUserInRole("Display");

		/**
		 * This will work because the uer actually has role 'ROLE_Servlet'!
		 * see https://docs.spring.io/spring-security/site/migrate/current/3-to-4/html5/migrate-3-to-4-jc.html#m3to4-role-prefixing-disable
		 */
		boolean isUserInRoleServlet = req.isUserInRole("Servlet"); //

		resp.getWriter().println("isUserInRole('Display')=" + isUserInRoleDisplay);
		resp.getWriter().println("isUserInRole('Servlet')=" + isUserInRoleServlet);

		resp.setStatus(HttpServletResponse.SC_OK);
	}
}
