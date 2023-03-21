/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;

import java.io.InputStream;
import java.util.Scanner;

/**
 * Central entry point to access the current SAP Cloud Platform
 * {@link Environment}.
 */
public class Environments {

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
			currentEnvironment = new ServiceBindingEnvironment();
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
		return new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(str -> vcapServices.toString()));
	}

}
