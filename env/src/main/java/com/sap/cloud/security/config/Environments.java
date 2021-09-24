/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.security.DefaultEnvironmentsProvider;
import com.sap.cloud.security.config.cf.CFEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.ServiceLoader;

import static com.sap.cloud.security.config.k8s.K8sConstants.KUBERNETES_SERVICE_HOST;

/**
 * Central entry point to access the current SAP Cloud Platform
 * {@link Environment}.
 */
public class Environments {

	static List<EnvironmentProvider> environmentProviders = new ArrayList() {
		{
			ServiceLoader.load(EnvironmentProvider.class).forEach(this::add);
			LoggerFactory.getLogger(Environments.class).info("loaded EnvironmentLoader service providers: {}", this);
		}
	};

	private static Environment currentEnvironment;

	private Environments() {
		// use factoryMethods instead
	}

	/**
	 * Determines the current type of {@link Environment}.
	 * 
	 * @return the current environment
	 */
	public static Environment getCurrent() {
		if (currentEnvironment == null) {
			if (environmentProviders.isEmpty()) {
				currentEnvironment = new DefaultEnvironmentsProvider().getCurrent();
			} else {
				currentEnvironment = environmentProviders.get(0).getCurrent();
			}
		}
		return currentEnvironment;
	}

	/**
	 * Reads {@link Environment} not from system environment but from
	 * {@link InputStream}. Is applicable only to CF environment and expects the
	 * input to be in VCAP services format.
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
