package com.sap.cloud.security.xsuaa.token.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.sap.cloud.security.xsuaa.api.AuthorizationMapper;

public class TenantAuthorizationMapper implements AuthorizationMapper {

	List<String> zonifiedReadWriteScopes = Arrays.asList("xs_authorization.", "xs_monitor.", "xs_user.", "xs_idp.");
	protected static final Log logger = LogFactory.getLog(TenantAuthorizationMapper.class);

	@Override
	public Set<String> filterScopes(Map<String, Object> tokenMap, Set<String> scopeSet) {
		Set<String> filteredSet = new HashSet<>();

		for (String scope : scopeSet) {
			String filteredScope = filterScope(scope);
			if (filteredScope != null) {
				filteredSet.add(filteredScope);
			}
		}
		logger.info(String.format("Mapped scopes from %s to %s", scopeSet, filteredSet));
		return filteredSet;
	}

	@Override
	public Set<GrantedAuthority> filterAuthorities(Map<String, Object> tokenMap, Set<GrantedAuthority> authoritiesSet) {
		Set<GrantedAuthority> filteredSet = new HashSet<>();

		for (GrantedAuthority authority : authoritiesSet) {
			String filteredScope = filterScope(authority.getAuthority());
			if (filteredScope != null) {
				filteredSet.add(new SimpleGrantedAuthority(filteredScope));
			}
		}
		return filteredSet;
	}

	private String filterScope(String scope) {
		String tenant = "example";
		for (String zonifiedReadWriteScope : zonifiedReadWriteScopes) {
			if (scope.equals(zonifiedReadWriteScope + tenant + ".read")) {
				return zonifiedReadWriteScope + "read";
			}
			if (scope.equals(zonifiedReadWriteScope + tenant + ".write")) {
				return zonifiedReadWriteScope + "write";
			}
		}

		if (scope.startsWith("openid")) {
			return "openid";
		}
		return null;
	}

}