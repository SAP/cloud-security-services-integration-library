package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

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
	 * Determines the current type of {@link Environment}.
	 *
	 * @return the current environment
	 */
	public static Environment getCurrent(InputStream input) throws IOException {
		Scanner scanner = new Scanner(input);
		//Reading line by line from scanner to StringBuffer
		StringBuffer vcapServices = new StringBuffer();
		while(scanner.hasNext()){
			vcapServices.append(scanner.nextLine());
		}
		return CFEnvironment.getInstance((str) -> vcapServices.toString(), (str) -> null);
	}

}
