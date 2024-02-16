/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security;

import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;

import static com.sap.cloud.security.config.ServiceConstants.XSUAA.APP_ID;

@Configuration
public class XsuaaAuthzConverter {

	@Bean
	public XsuaaTokenAuthorizationConverter multipleXsuaaConfigAuthzConverter(
			XsuaaServiceConfigurations xsuaaConfigs) {
		return new XsuaaTokenAuthorizationConverterExt (
				xsuaaConfigs.getConfigurations().get(0).getProperty(APP_ID),
				xsuaaConfigs.getConfigurations().get(1).getProperty(APP_ID));
	}

	private static class XsuaaTokenAuthorizationConverterExt extends XsuaaTokenAuthorizationConverter {

		private final String appId;
		private final String appId2;

		public XsuaaTokenAuthorizationConverterExt(String appId, String appId2) {
			super(appId);
			this.appId = appId;
			this.appId2 = appId2;
		}

		@Override
		protected Collection<GrantedAuthority> localScopeAuthorities(Collection<String> scopes) {
			Collection<GrantedAuthority> localScopeAuthorities = new ArrayList<>();
			for (String scope : scopes) {
				if (scope.startsWith(appId + ".")) {
					localScopeAuthorities.add(new SimpleGrantedAuthority(scope.substring(appId.length() + 1)));
				} else if (scope.startsWith(appId2 + ".")){
					localScopeAuthorities.add(new SimpleGrantedAuthority(scope.substring(appId2.length() + 1)));
				}
			}
			return localScopeAuthorities;
		}
	}
}
