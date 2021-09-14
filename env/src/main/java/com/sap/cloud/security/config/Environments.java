/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;
import com.sap.cloud.security.token.ProviderNotFoundException;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenFactory;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.ServiceLoader;

/**
 * Central entry point to access the current SAP Cloud Platform
 * {@link Environment}.
 */
public class Environments {
	static List<EnvironmentLoader> environments = new ArrayList() {
		{
			ServiceLoader.load(EnvironmentLoader.class).forEach(this::add);
			LoggerFactory.getLogger(Environments.class).info("loaded EnvironmentLoader service providers: {}", this);
		}
	};

	private Environments() {
		// use factory methods instead
	}

	/**
	 * Determines the current type of {@link Environment}.
	 * 
	 * @return the current environment
	 */
	public static Environment getCurrent() {
		if (environments.isEmpty()) {
			throw new ProviderNotFoundException("No EnvironmentLoader service implementation found in the classpath");
		}
		return environments.get(0).getCurrent();
	}

	/**
	 * Reads {@link Environment} not from system environment but from
	 * {@link InputStream}.
	 * 
	 * @param input
	 *            e.g. from file
	 * @return the environment
	 */
	public static Environment readFromInput(InputStream input) {
		Scanner scanner = new Scanner(input);
		StringBuilder vcapServices = new StringBuilder();
		while (scanner.hasNext()) {
			vcapServices.append(scanner.nextLine());
		}
		return CFEnvironment.getInstance(str -> vcapServices.toString(), str -> null);
	}

}
