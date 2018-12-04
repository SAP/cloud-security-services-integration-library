/**
 * 
 */
package com.sap.cloud.security.xsuaa;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(factory = XsuaaSpringOAuth2PropertySourceFactory.class, value = { "" })
public class XsuaaSpringOAuth2Configuration {

}
