package com.sap.cloud.security.spring.autoconfig;

import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * {@link EnableAutoConfiguration} uses a {@link com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy}, which keeps the {@code com.sap.cloud.security.token.SecurityContext} in
 * sync
 *
 * <p>
 * Can be disabled with
 * {@code @EnableAutoConfiguration(exclude={SecurityContextAutoConfiguration.class})}
 * or with property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnProperty(name = "sap.spring.security.hybrid.auto", havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(HybridAuthorizationAutoConfiguration.class)
public class SecurityContextAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(SecurityContextHolderStrategy.class)
    public MethodInvokingFactoryBean methodInvokingFactoryBean() {
        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
        methodInvokingFactoryBean.setTargetClass(SecurityContextHolder.class);
        methodInvokingFactoryBean.setTargetMethod("setStrategyName");
        methodInvokingFactoryBean.setArguments("com.sap.cloud.security.spring.token.authentication.JavaSecurityContextHolderStrategy");
        return methodInvokingFactoryBean;
    }
}
