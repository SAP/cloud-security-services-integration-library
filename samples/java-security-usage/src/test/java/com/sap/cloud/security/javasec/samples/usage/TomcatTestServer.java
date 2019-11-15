package com.sap.cloud.security.javasec.samples.usage;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.io.FileUtils;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wiremock.com.google.common.io.Files;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;

public class TomcatTestServer extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(TomcatTestServer.class);

	private final int port;
	private final String webappDir;
	private Tomcat tomcat;
	private File baseDir;

	public TomcatTestServer(int port, String webappDir) {
		this.port = port;
		this.webappDir = new File(webappDir).getAbsolutePath();
		baseDir = Files.createTempDir();
		tomcat = new Tomcat();
	}

	@Override
	protected void before() {
		start();
	}

	@Override
	protected void after() {
		try {
			tomcat.stop();
			tomcat.destroy();
			FileUtils.deleteDirectory(baseDir);
		} catch (LifecycleException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void start() {
		tomcat.setPort(port);
		tomcat.setBaseDir(baseDir.getAbsolutePath());
		try {
			tomcat.addWebapp("", webappDir);
			tomcat.start();
		} catch (LifecycleException | ServletException e) {
			logger.error("Failed to start tomcat server", e);
		}
	}
}
