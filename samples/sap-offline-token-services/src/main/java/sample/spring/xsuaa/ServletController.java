package sample.spring.xsuaa;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/hello-servlet")
public class ServletController extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		resp.getWriter().write("remoteUser: " + req.getRemoteUser() + "\n");
		resp.getWriter().write("user principal: " + req.getUserPrincipal() + "\n");
		resp.getWriter().write("has role Display: " + req.isUserInRole("Display") + "\n");
		if (req.isUserInRole("Display")) {
			resp.getWriter().write("Success!");
		}
		resp.setStatus(HttpServletResponse.SC_OK);
	}
}
