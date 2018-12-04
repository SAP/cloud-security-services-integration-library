/**
 * 
 */
package com.sap.cloud.security.xsuaa;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({ XsuaaSpringOAuth2Configuration.class })
public @interface EnableXsuaaOauth2Config {

}
