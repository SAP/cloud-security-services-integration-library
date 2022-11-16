/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;

public class BenchmarkUtil {

	static final int WARMUP_ITERATIONS = 10_000;
	static final int BENCHMARK_ITERATIONS = 100_000;
	private static final Logger LOGGER = LoggerFactory.getLogger(BenchmarkUtil.class);

	public static String getSystemInfo() {
		String systemInfo =  String.format("Running on %s's %s %s, home is %s", System.getProperty("java.vm.vendor"),
				System.getProperty("java.vm.name"), System.getProperty("java.vm.version"),
				System.getProperty("java.home"));
		String compilerInfo = String.format("   %s, %s", System.getProperty("sun.management.compiler"),
				System.getProperty("java.vm.info"));
		return systemInfo + System.lineSeparator() + compilerInfo;
	}

	public static Result execute(int warmupIterations, int iterations, CheckedSupplier<Object> toTestFn) {
		// Warm up phase
		// 10 000 iterations shall give the JVM sufficient time to native-compile the code, so
		// we're hopefully not hitting a compile phase when benchmarking.
		// It is observable that higher values lead to effectively higher measured throughput.
		executeInternal(warmupIterations, toTestFn);

		// actual benchmark run
		Duration duration = executeInternal(iterations, toTestFn);
		return new Result(iterations, duration);
	}

	public static Result execute(CheckedSupplier<Object> toTestFn) {
		return execute(WARMUP_ITERATIONS, BENCHMARK_ITERATIONS, toTestFn);
	}

	private static Duration executeInternal(int localIterations, CheckedSupplier<Object> toTestFn) {
		// Trick JVM escape analysis optimizations that may optimize out calls to validate entirely
		final Instant start = Instant.now();
		for (int i = 0; i < localIterations; ++i) {
			try {
				LOGGER.info("call function: {}", i);
				toTestFn.get();
			} catch (Exception e) {
				LOGGER.info("error calling function: {}", e.getMessage());
			}
		}
		final Instant stop = Instant.now();
		return Duration.between(start, stop);
	}

	public static class Result {
		public final int iterations;
		public final Duration duration;

		public Result(int iterations, Duration duration) {
			this.iterations = iterations;
			this.duration = duration;
		}

		public String getFormattedResult() {
			return String.format("%d runs in %d milliseconds -> %.2f runs/second",
					iterations, duration.toMillis(), (iterations * 1000.0) / duration.toMillis());
		}

		@Override
		public String toString() {
			return String.format("Benchmark result: %s", getFormattedResult());
		}
	}

	@FunctionalInterface
	public interface CheckedSupplier<T> {
		public T get() throws Exception;
	}
}
