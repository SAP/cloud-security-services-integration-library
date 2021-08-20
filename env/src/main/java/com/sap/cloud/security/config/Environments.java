/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;


import com.sap.cloud.security.config.cf.CFEnvironment;

import java.io.InputStream;
import java.util.Scanner;

/**
 * Central entry point to access the current SAP Cloud Platform
 * {@link Environment}.
 */
public class Environments {

	private static final Environment cfEnvironment = CFEnvironment.getInstance(); // singleton

	private Environments() {
		// use factoryMethods instead
	}

	/**
	 * Determines the current type of {@link Environment}.
	 * 
	 * @return the current environment
	 */
	public static Environment getCurrent() {
		// TODO Kubernetes: probe in which environment it runs currently: CF or
		return cfEnvironment;
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
