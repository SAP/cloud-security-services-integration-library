/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import javax.annotation.Nonnull;

import static com.sap.cloud.security.spring.autoconfig.SapSecurityProperties.SAP_SPRING_SECURITY_HYBRID;
import static com.sap.cloud.security.spring.autoconfig.SapSecurityProperties.SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN;

public class Conditions {

	private Conditions() {
	}

	static class HybridProofTokenCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			Environment env = context.getEnvironment();
			String proofTokenEnabled = env.getProperty(SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN);
			String hybridEnabled = env.getProperty(SAP_SPRING_SECURITY_HYBRID);

			return proofTokenEnabled != null && proofTokenEnabled.equals(
					"true") && (hybridEnabled == null || hybridEnabled.equals("true"));
		}
	}

	static class HybridDefaultCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			Environment env = context.getEnvironment();
			String proofTokenEnabled = env.getProperty(SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN);
			String hybridEnabled = env.getProperty(SAP_SPRING_SECURITY_HYBRID);

			return (proofTokenEnabled == null || proofTokenEnabled.equals(
					"false")) && (hybridEnabled == null || hybridEnabled.equals("true"));
		}
	}
}
