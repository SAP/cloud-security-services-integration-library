package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceDefault;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AdcServiceConfiguration {

	@Value("${ADC_URL:http://localhost:8181}")
	private String adcUrl;

	@Bean
	@ConditionalOnMissingBean(AdcService.class)
	public AdcService adcService() {
		return new AdcServiceDefault(adcUrl);
	}

}
