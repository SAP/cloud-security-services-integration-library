package com.sap.cloud.security.xsuaa.mock;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.mock.autoconfiguration.XsuaaMockAutoConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { XsuaaMockAutoConfiguration.class, MockXsuaaServiceConfiguration.class })
public class ApplicationTest {

	@Test
	public void contextLoads() {
	}

}
