package com.sap.cloud.security.javasec.samples.usage;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TomcatTestServer {

	private static final Logger logger = LoggerFactory.getLogger(TomcatTestServer.class);

	private final String webappDir;
	private final int port;
	private ExecutorService executorService;

	// TODO 14.11.19 c5295400: make tomcat launch at free random port?
	public TomcatTestServer(String webappDir, int port) {
		this.webappDir = webappDir;
		this.port = port;
		executorService = Executors.newFixedThreadPool(1);
	}

	public void start() throws InterruptedException {
		CountDownLatch lock = new CountDownLatch(1);

		executorService.submit(() -> {
			Tomcat tomcat = new Tomcat();
			tomcat.setPort(port);
			try {
				tomcat.addWebapp("", webappDir);
				tomcat.start();
			} catch (LifecycleException | ServletException e) {
				logger.error("Failed to start tomcat server", e);
			}
			lock.countDown();
			tomcat.getServer().await();
		});
		lock.await(); // wait for tomcat to start in thread
	}

	public void stop() {
		executorService.shutdown();
	}
}
