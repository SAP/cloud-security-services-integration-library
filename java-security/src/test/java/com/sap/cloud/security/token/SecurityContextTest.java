package com.sap.cloud.security.token;

import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SecurityContextTest {

	private static final Token TOKEN = new MockTokenBuilder().build();
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();

	@Before
	public void setUp() {
		SecurityContext.clearToken();
	}

	@Test
	public void setTokenAndRetrieve_NullToken() {
		SecurityContext.setToken(TOKEN);
		SecurityContext.setToken(null);
		assertThat(SecurityContext.getToken()).isNull();
	}

	@Test
	public void getInitialToken_isNull() {
		Token token = SecurityContext.getToken();

		assertThat(token).isNull();
	}

	@Test
	public void setTokenAndGet() {
		SecurityContext.setToken(TOKEN);
		Token token = SecurityContext.getToken();

		assertThat(token).isEqualTo(TOKEN);
	}

	@Test
	public void clear_removesToken() {
		SecurityContext.setToken(TOKEN);
		SecurityContext.clearToken();
		Token token = SecurityContext.getToken();

		assertThat(token).isNull();
	}

	@Test
	public void tokenNotAvailableInDifferentThread() throws ExecutionException, InterruptedException {
		SecurityContext.setToken(TOKEN);

		Future<Token> tokenInOtherThread = executorService.submit(() -> SecurityContext.getToken());

		assertThat(tokenInOtherThread.get()).isNull();
	}

	@Test
	public void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		SecurityContext.setToken(TOKEN);

		executorService.submit(() -> SecurityContext.clearToken()).get(); // run and await other thread

		assertThat(SecurityContext.getToken()).isEqualTo(TOKEN);
	}

}