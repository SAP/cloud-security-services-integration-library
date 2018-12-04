/**
 * 
 */
package com.sap.cloud.security.xsuaa.util;

import org.junit.AssumptionViolatedException;
import org.junit.internal.runners.model.EachTestNotifier;
import org.junit.internal.runners.statements.Fail;
import org.junit.runner.Description;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.sap.cloud.security.xsuaa.XsuaaServicesParser;

/**
 * Custom Test Runner: Verify exception in the ApplicationContext loading in
 * case of an invalid binding
 * 
 * @see {@link XsuaaServicesParser#getJSONObjectFromTag}
 * 
 *
 *
 */
public class CustomSpringRunner extends SpringJUnit4ClassRunner {

	public CustomSpringRunner(Class<?> clazz) throws InitializationError {
		super(clazz);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.test.context.junit4.SpringJUnit4ClassRunner#runChild(org.
	 * junit.runners.model.FrameworkMethod,
	 * org.junit.runner.notification.RunNotifier)
	 */
	@Override
	protected void runChild(FrameworkMethod frameworkMethod, RunNotifier notifier) {
		Description description = describeChild(frameworkMethod);
		if (isTestMethodIgnored(frameworkMethod)) {
			notifier.fireTestIgnored(description);
		} else {
			Statement statement;
			try {
				statement = methodBlock(frameworkMethod);
			} catch (Throwable ex) {
				statement = new Fail(ex);
			}
			checkLeaf(statement, description, notifier);
		}
	}


	/**
	 * Runs a {@link Statement} that represents a leaf (aka atomic) test. If there
	 * is the (expected) ApplicationContext Instantiation exception the test is ok
	 * 
	 */
	private void checkLeaf(Statement statement, Description description, RunNotifier notifier) {
		EachTestNotifier eachNotifier = new EachTestNotifier(notifier, description);
		eachNotifier.fireTestStarted();
		try {
			statement.evaluate();
		} catch (AssumptionViolatedException e) {
			eachNotifier.addFailedAssumption(e);
		} catch (Throwable e) {
			Throwable rootCause = e.getCause().getCause();
			boolean expectedException = false;
			if (rootCause instanceof RuntimeException) {
				if (rootCause.getMessage().startsWith("Found more than one xsuaa binding.")) {
					// expected exception -> so the test is ok
					expectedException = true;
				}
			}
			if (!expectedException) {
				eachNotifier.addFailure(e);
			}
		} finally {
			eachNotifier.fireTestFinished();
		}
	}

}
