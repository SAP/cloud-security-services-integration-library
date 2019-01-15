package com.sap.cloud.security.xsuaa.mock;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(properties = { "xsuaa.url=${mockxsuaaserver.url}", "xsuaa.identityzoneid= uaa" }, classes = { XsuaaMockWebServer.class, XsuaaRequestDispatcher.class })
public class ApplicationTest {

	@Test
	public void contextLoads() {
	}

}
