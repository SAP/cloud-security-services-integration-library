/**
 * 
 */
package com.sap.cloud.security.xsuaa.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * Inject new Key-Value Pairs in the runtime environment
 * 
 *
 *
 */
public final class EnvironmentInjectionUtil {

	private EnvironmentInjectionUtil() {
	}

	public static void injectEnvironmentVariable(String key, String value) throws Exception {

		Class<?> processEnvironmentVariable = Class.forName("java.lang.ProcessEnvironment$Variable");
		Method variableFactoryMethod = processEnvironmentVariable.getMethod("valueOfQueryOnly", String.class);
		variableFactoryMethod.setAccessible(true);
		Object keyVariable = variableFactoryMethod.invoke(null, key);

		Class<?> processEnvironmentValue = Class.forName("java.lang.ProcessEnvironment$Value");
		Method valueFactoryMethod = processEnvironmentValue.getMethod("valueOfQueryOnly", String.class);
		valueFactoryMethod.setAccessible(true);
		Object valueVariable = valueFactoryMethod.invoke(null, value);

		Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");
		Field mapField = getAccessibleField(processEnvironment, "theEnvironment");
		@SuppressWarnings("unchecked")
		Map<Object, Object> map = (Map<Object, Object>) mapField.get(null);
		map.put(keyVariable, valueVariable);
	}

	private static Field getAccessibleField(Class<?> clazz, String fieldName) throws NoSuchFieldException {

		Field field = clazz.getDeclaredField(fieldName);
		field.setAccessible(true);
		return field;
	}


}
