package com.sap.cloud.security.samples;

import com.sap.cloud.security.servlet.XsuaaTokenAuthenticator;
import com.sap.cloud.security.test.jetty.JettyTokenAuthenticator;
import org.eclipse.jetty.annotations.AnnotationConfiguration;
import org.eclipse.jetty.plus.webapp.EnvConfiguration;
import org.eclipse.jetty.plus.webapp.PlusConfiguration;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.*;

import java.net.URL;
import java.util.Arrays;

/**
 * This class is used to start the sample as standalone application which does not rely on
 * a application server runtime.
 * TODO only needed because the java build pack does only support the servlet security annotations
 * in conjunction with the old Java Container Security library. As soon as the SAP java build pack
 * supports the new java security library, this class can be removed.
 */
public class Application {

	public static void main(String[] args) throws Exception {
		Server server = createJettyServer();
		server.start();
		server.join();
	}

	// bootstrapping jetty server
	private static Server createJettyServer() {
		WebAppContext context = new WebAppContext();
		ConstraintSecurityHandler security = new ConstraintSecurityHandler();
		security.setAuthenticator(new JettyTokenAuthenticator(new XsuaaTokenAuthenticator()));
		context.setSecurityHandler(security);
		context.setConfigurations(new Configuration[] {
				new AnnotationConfiguration(), new WebXmlConfiguration(),
				new WebInfConfiguration(), new PlusConfiguration(), new MetaInfConfiguration(),
				new FragmentConfiguration(), new EnvConfiguration() });
		context.setContextPath("/");
		context.setResourceBase("src/main/java/webapp");

		// needed so that annotations from this project are also scanned
		context.setParentLoaderPriority(true);
		URL classes = HelloJavaServlet.class
				.getProtectionDomain()
				.getCodeSource()
				.getLocation();
		context.getMetaData()
				.setWebInfClassesDirs(
						Arrays.asList(Resource.newResource(classes)));

		Server server = new Server(8080);
		server.setHandler(context);
		return server;
	}
}
