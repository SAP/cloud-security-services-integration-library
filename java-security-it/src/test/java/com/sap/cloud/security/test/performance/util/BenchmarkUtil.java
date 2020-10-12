package com.sap.cloud.security.test.performance.util;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

public class BenchmarkUtil {

	static final int WARMUP_ITERATIONS = 10_000;
	static final int BENCHMARK_ITERATIONS = 100_000;

	public static String getSystemInfo() {
		String systemInfo =  String.format("Running on %s's %s %s, home is %s", System.getProperty("java.vm.vendor"),
				System.getProperty("java.vm.name"), System.getProperty("java.vm.version"),
				System.getProperty("java.home"));
		String compilerInfo = String.format("   %s, %s", System.getProperty("sun.management.compiler"),
				System.getProperty("java.vm.info"));
		return systemInfo + System.lineSeparator() + compilerInfo;
	}

	public static Result execute(int iterations, Supplier<Object> toTestFn) {
		// Warm up phase
		// 10 000 iterations shall giver the JVM sufficient time to native-compile the code, so
		// we're hopefully not hitting a compile phase when benchmarking.
		// It is observable that higher values lead to effectively higher measured throughput.
		executeInternal(WARMUP_ITERATIONS, toTestFn);

		// actual benchmark run
		Duration duration = executeInternal(iterations, toTestFn);
		return new Result(iterations, duration);
	}

	public static Result execute(Supplier<Object> toTestFn) {
		return execute(BENCHMARK_ITERATIONS, toTestFn);
	}

	private static Duration executeInternal(int localIterations, Supplier<Object> validationFn) {
		// Trick JVM escape analysis optimizations that may optimize out calls to validate entirely
		Object obj;
		final Instant start = Instant.now();
		for (int i = 0; i < localIterations; ++i) {
			obj = validationFn.get();
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
}
