package com.sap.cloud.security.token;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

public interface TokenProvider {

	static List<TokenFactory> providers() {
		List<TokenFactory> services = new ArrayList<>();
		ServiceLoader<TokenFactory> loader = ServiceLoader.load(TokenFactory.class);
		loader.forEach(services::add);
		return services;
	}

	static TokenFactory provider(String providerName) {
		ServiceLoader<TokenFactory> loader = ServiceLoader.load(TokenFactory.class);
		for (TokenFactory provider : loader) {
			if (providerName.equals(provider.getClass().getName())) {
				return provider;
			}
		}
		throw new ProviderNotFoundException("Token provider " + providerName + " not found");
	}
}
