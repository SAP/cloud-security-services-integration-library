/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

public class SecurityContextTest {

  private static Token TOKEN;
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();

  @Before
  public void setUp() {
    SecurityContext.clearContext();
    SecurityContext.registerIdTokenExtension(null);
    SecurityContext.registerXsuaaTokenExtension(null);
    TOKEN = new MockTokenBuilder().build();
  }

  @Test
  public void clearContext_contextIsReplaced() {
    SecurityContext.setToken(TOKEN);
    SecurityContext.clearContext();
    assertThat(SecurityContext.getToken()).isNull();
  }

  @Test
  public void clear_contextIsCleared() {
    SecurityContext.setToken(TOKEN);
    SecurityContext.clear();
    assertThat(SecurityContext.getToken()).isNull();
  }

	@Test
	public void setTokenAndRetrieve_NullToken() {
		SecurityContext.setToken(TOKEN);
		SecurityContext.setToken(null);
		assertThat(SecurityContext.getToken()).isNull();
	}

  @Test
  public void getToken_isNull() {
		Token token = SecurityContext.getToken();

		assertThat(token).isNull();
  }

  @Test
  public void getInitialToken_isNull() {
    Token token = SecurityContext.getInitialToken();

    assertThat(token).isNull();
	}

	@Test
	public void setTokenAndGet() {
		SecurityContext.setToken(TOKEN);
		assertThat(SecurityContext.getToken()).isEqualTo(TOKEN);
    assertThat(SecurityContext.getInitialToken()).isEqualTo(TOKEN);
	}

  @Test
  public void overwriteToken() {
    SecurityContext.updateToken(TOKEN);
    assertThat(SecurityContext.getToken()).isEqualTo(TOKEN);
    assertThat(SecurityContext.getInitialToken()).isNull();
  }

	@Test
	public void clear_removesToken() {
		SecurityContext.setToken(TOKEN);
    SecurityContext.clearContext();

		assertThat(SecurityContext.getToken()).isNull();
    assertThat(SecurityContext.getInitialToken()).isNull();
    assertThat(SecurityContext.getIdToken()).isNull();
    assertThat(SecurityContext.getXsuaaToken()).isNull();
	}

	@Test
	public void tokenNotAvailableInDifferentThread() throws ExecutionException, InterruptedException {
		SecurityContext.setToken(TOKEN);

    Future<Token> tokenInOtherThread = executorService.submit(SecurityContext::getToken);

		assertThat(tokenInOtherThread.get()).isNull();
	}

	@Test
	public void clearingTokenInDifferentThreadDoesNotAffectMainThread()
			throws ExecutionException, InterruptedException {
		SecurityContext.setToken(TOKEN);

    executorService.submit(SecurityContext::clearContext).get(); // run and await other thread

		assertThat(SecurityContext.getToken()).isEqualTo(TOKEN);
	}

	@Test
	public void getAccessTokenReturnsNullIfTokenDoesNotImplementInterface() {
		SecurityContext.setToken(TOKEN);
		assertThat(SecurityContext.getAccessToken()).isNull();
	}

	@Test
	public void getAccessTokenReturns() throws IOException {
		AccessToken accessToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
		SecurityContext.setToken(accessToken);
		assertThat(SecurityContext.getAccessToken()).isEqualTo(accessToken);
	}

	@Test
	public void setGetRemoveServicePlans() {
		SecurityContext.setServicePlans("\"plan1\" , \"plan \"two\"\",\"plan3\"");
		assertThat(SecurityContext.getServicePlans()).containsExactly("plan1", "plan \"two\"", "plan3");
		SecurityContext.clearServicePlans();
		assertThat(SecurityContext.getServicePlans()).isNull();
	}

  @Test
  public void getIdToken_withoutExtension_returnsNull() {
    assertNull(SecurityContext.getIdToken());
  }

  @Test
  public void getIdToken_idTokenPresentAndValid_returnsTokenValue() {
    when(TOKEN.getTokenValue()).thenReturn("valid-id-token");
    when(TOKEN.getExpiration()).thenReturn(Instant.now().plus(10, ChronoUnit.MINUTES));

    setIdTokenStorage();

    Token result = SecurityContext.getIdToken();

    assertEquals("valid-id-token", result.getTokenValue());
    assertSame(TOKEN, getIdTokenStorage());
  }

  @Test
  public void getIdToken_tokenIsExpiredButExtensionSet_removesExpiredTokenAndResolvesNewToken()
      throws IOException {
    IdTokenExtension extension = mock(IdTokenExtension.class);
    SecurityContext.registerIdTokenExtension(extension);
    when(TOKEN.getTokenValue()).thenReturn("expired-token");
    when(TOKEN.getExpiration()).thenReturn(Instant.now().minus(1, ChronoUnit.MINUTES));
    when(extension.resolveIdToken(TOKEN))
        .thenReturn(Token.create(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8)));

    setIdTokenStorage();

    Token result = SecurityContext.getIdToken();

    assertEquals(
        IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8), result.getTokenValue());
    assertEquals(result, getIdTokenStorage());
  }

  @Test
  public void getIdToken_usesExtension_whenNoTokenStored() throws IOException {
    IdTokenExtension extension = mock(IdTokenExtension.class);
    when(extension.resolveIdToken(null))
        .thenReturn(Token.create(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8)));
    SecurityContext.registerIdTokenExtension(extension);

    Token result = SecurityContext.getIdToken();

    assertEquals(
        IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8), result.getTokenValue());
    verify(extension, times(1)).resolveIdToken(null);
    assertNotNull(getIdTokenStorage(), "Resolved token should be stored in ThreadLocal");
    assertEquals(
        IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8),
        getIdTokenStorage().getTokenValue());
  }

  @Test
  public void getXsuaaToken_withoutExtension_returnsNull() {
    assertNull(SecurityContext.getXsuaaToken());
  }

  @Test
  public void getXsuaaToken_xsuaaTokenTokenPresentAndValid_returnsTokenValue() {
    when(TOKEN.getTokenValue()).thenReturn("valid-xsuaa-token");
    when(TOKEN.getExpiration()).thenReturn(Instant.now().plus(10, ChronoUnit.MINUTES));

    setXsuaaTokenStorage();

    Token result = SecurityContext.getXsuaaToken();

    assertEquals("valid-xsuaa-token", result.getTokenValue());
    assertSame(TOKEN, getXsuaaTokenStorage());
  }

  @Test
  public void getXsuaaToken_tokenIsExpiredButExtensionSet_removesExpiredTokenAndResolvesNewToken()
      throws IOException {
    XsuaaTokenExtension extension = mock(XsuaaTokenExtension.class);
    SecurityContext.registerXsuaaTokenExtension(extension);
    when(TOKEN.getTokenValue()).thenReturn("expired-token");
    when(TOKEN.getExpiration()).thenReturn(Instant.now().minus(1, ChronoUnit.MINUTES));
    when(extension.resolveXsuaaToken(TOKEN))
        .thenReturn(Token.create(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8)));

    setXsuaaTokenStorage();

    Token result = SecurityContext.getXsuaaToken();

    assertEquals(
        IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8), result.getTokenValue());
    assertEquals(result, getXsuaaTokenStorage());
  }

  @Test
  public void getXsuaaToken_usesExtension_whenNoTokenStored() throws IOException {
    XsuaaTokenExtension extension = mock(XsuaaTokenExtension.class);
    when(extension.resolveXsuaaToken(null))
        .thenReturn(Token.create(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8)));
    SecurityContext.registerXsuaaTokenExtension(extension);

    Token result = SecurityContext.getXsuaaToken();

    assertEquals(
        IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8), result.getTokenValue());
    verify(extension, times(1)).resolveXsuaaToken(null);
    assertNotNull(getXsuaaTokenStorage(), "Resolved token should be stored in ThreadLocal");
    assertEquals(
        IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8),
        getXsuaaTokenStorage().getTokenValue());
  }

  private static void setIdTokenStorage() {
    try {
      var field = SecurityContext.class.getDeclaredField("contextStorage");
      field.setAccessible(true);
      ThreadLocal<?> tl = (ThreadLocal<?>) field.get(null);

      Object contextHolder = tl.get();
      var idTokenField = contextHolder.getClass().getDeclaredField("idToken");
      idTokenField.setAccessible(true);
      idTokenField.set(contextHolder, TOKEN);
    } catch (Exception e) {
      fail(e);
    }
  }

  private static Token getIdTokenStorage() {
    try {
      var field = SecurityContext.class.getDeclaredField("contextStorage");
      field.setAccessible(true);
      ThreadLocal<?> tl = (ThreadLocal<?>) field.get(null);

      Object contextHolder = tl.get();
      var idTokenField = contextHolder.getClass().getDeclaredField("idToken");
      idTokenField.setAccessible(true);
      return (Token) idTokenField.get(contextHolder);
    } catch (Exception e) {
      fail(e);
      return null;
    }
  }

  private static void setXsuaaTokenStorage() {
    try {
      var field = SecurityContext.class.getDeclaredField("contextStorage");
      field.setAccessible(true);
      ThreadLocal<?> tl = (ThreadLocal<?>) field.get(null);

      Object contextHolder = tl.get();
      var xsuaaTokenField = contextHolder.getClass().getDeclaredField("xsuaaToken");
      xsuaaTokenField.setAccessible(true);
      xsuaaTokenField.set(contextHolder, TOKEN);
    } catch (Exception e) {
      fail(e);
    }
  }

  private static Token getXsuaaTokenStorage() {
    try {
      var field = SecurityContext.class.getDeclaredField("contextStorage");
      field.setAccessible(true);
      ThreadLocal<?> tl = (ThreadLocal<?>) field.get(null);

      Object contextHolder = tl.get();
      var xsuaaTokenField = contextHolder.getClass().getDeclaredField("xsuaaToken");
      xsuaaTokenField.setAccessible(true);
      return (Token) xsuaaTokenField.get(contextHolder);
    } catch (Exception e) {
      fail(e);
      return null;
    }
  }
}