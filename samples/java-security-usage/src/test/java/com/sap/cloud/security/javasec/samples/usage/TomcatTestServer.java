package com.sap.cloud.security.javasec.samples.usage;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;

// TODO provide Rule with java-security-test
public class TomcatTestServer extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(TomcatTestServer.class);

	private final int port;
	private final String webappDir;
	private Tomcat tomcat;
	private TemporaryFolder baseDir;

	public TomcatTestServer(int port, String webappDir) {
		this.port = port;
		this.webappDir = new File(webappDir).getAbsolutePath();
		baseDir = new TemporaryFolder();
		tomcat = new Tomcat();
	}

	@Override
	protected void before() throws IOException {
		start();
	}

	@Override
	protected void after() {
		try {
			tomcat.stop();
			tomcat.destroy();
			baseDir.delete();
		} catch (LifecycleException e) {
			logger.error("Failed to properly stop the tomcat server!");
			throw new RuntimeException(e);
		}
	}

	private void start() throws IOException {
		tomcat.setPort(port);
		baseDir.create();
		tomcat.setBaseDir(baseDir.getRoot().getAbsolutePath());
		try {
			tomcat.addWebapp("", webappDir);
			tomcat.start();
		} catch (LifecycleException | ServletException e) {
			logger.error("Failed to start the tomcat server!");
			throw new RuntimeException(e);
		}
	}
}
