package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.ADCExecutor;
import com.sap.cloud.security.cas.client.ADCService;
import com.sap.cloud.security.cas.client.SpringADCService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Optional;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		ConfigurableApplicationContext ctx = SpringApplication.run(Application.class, args);

		// TODO switch to DefaultADCService
		// RestOperations restOperations = ctx.getBean(RestOperations.class); // raises NoSuchBeanDefinitionException
		ADCService adcService = new SpringADCService(new RestTemplate());

		URI adcUrl = URI.create(Optional.ofNullable(ctx.getEnvironment().getProperty("OPA_URL"))
				.orElse("http://localhost:8181"));
		try {
			if(!adcService.ping(adcUrl)) {
				ADCExecutor.get().start();
				// TODO required? adcService.ping(adcUrl);
			}
		} catch (Exception e){
			System.out.println("ADC Start error: ");
			System.out.println(e.getStackTrace());
		}
	}

}
