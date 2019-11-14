package com.sap.cloud.security.javasec.samples.usage;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

public class TomcatTestServer {

	private static final Logger logger = LoggerFactory.getLogger(TomcatTestServer.class);

	// TODO 14.11.19 c5295400: find free random port
	public static final int TOMCAT_PORT = 8281;

	static void start(String webappPath) throws InterruptedException {
		CountDownLatch lock = new CountDownLatch(1);

		Executors.newFixedThreadPool(1).submit(() -> {
			Tomcat tomcat = new Tomcat();
			tomcat.setPort(TOMCAT_PORT);
			try {
				tomcat.addWebapp("", webappPath);
				tomcat.start();
			} catch (LifecycleException | ServletException e) {
				logger.error("Failed to start tomcat server", e);
			}
			lock.countDown();
			tomcat.getServer().await();
		});

		lock.await(); // wait for tomcat to start in thread
	}
}
