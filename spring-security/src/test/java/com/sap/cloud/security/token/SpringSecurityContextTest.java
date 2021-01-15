package com.sap.cloud.security.token;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.authentication.HybridJwtDecoder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;


public class SpringSecurityContextTest {
    Token xsuaaToken;
    Token sapIdToken;
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Before
    public void setUp() {
        xsuaaToken = JwtGenerator.getInstance(XSUAA, "theClientId")
                .withAppId("xsapp")
                .withLocalScopes("Scope1").createToken();
        sapIdToken = JwtGenerator.getInstance(IAS, "theClientId").createToken();
        SpringSecurityContext.clear();
    }

    @Test(expected = AccessDeniedException.class) // Access forbidden: not authenticated
    public void getSecurityContextRaiseAccessDeniedExceptionIfNotInitialized() {
        SpringSecurityContext.getToken();
    }

    @Test(expected = IllegalArgumentException.class) // Passed JwtDecoder instance must be of type 'XsuaaJwtDecoder'
    public void initSecurityContextRaiseExceptionIfNotXsuaaJwtDecoder() {
        String message = "";
        SpringSecurityContext.init(xsuaaToken.getTokenValue(), new JwtDecoder() {
            @Override
            public Jwt decode(String s) throws JwtException {
                return HybridJwtDecoder.parseJwt(xsuaaToken);
            }
        }, "xsapp");
    }


    @Test
    public void getToken_fromEmptySecurityContext_isNull() {
        assertThrows(AccessDeniedException.class, () -> SpringSecurityContext.getAccessToken());
        assertThrows(AccessDeniedException.class, () -> SpringSecurityContext.getToken());
    }

    @Test
    public void getToken() {
        setToken(sapIdToken);
        assertEquals(sapIdToken, SpringSecurityContext.getToken());

        setToken(xsuaaToken);
        assertEquals(xsuaaToken, SpringSecurityContext.getToken());
    }

    @Test
    public void getAccessToken() {
        setToken(xsuaaToken);
        assertEquals(xsuaaToken, SpringSecurityContext.getAccessToken());
    }

    @Test
    public void getAccessTokenScopes() {
        setToken(xsuaaToken);
        assertFalse(SpringSecurityContext.getAccessToken().hasLocalScope("Scope3"));
        assertTrue(SpringSecurityContext.getAccessToken().hasLocalScope("Scope1"));
    }

    @Test
    public void getAccessTokenReturnsNull_inCaseOfIasToken() {
        setToken(sapIdToken);
        assertNull(SpringSecurityContext.getAccessToken()); // shall throw exception?
    }

    @Test
    public void getTokenReturnsIasOidcToken() {
        setToken(sapIdToken);
        assertEquals(IAS, SpringSecurityContext.getToken().getService());
        assertEquals("theClientId", SpringSecurityContext.getToken().getClientId());
    }

    @Test
    public void clear_removesToken() {
        setToken(xsuaaToken);
        SpringSecurityContext.clear();

        assertThrows(AccessDeniedException.class, () -> SpringSecurityContext.getToken());
        assertThrows(AccessDeniedException.class, () -> SpringSecurityContext.getAccessToken());
    }

    //@Test
    public void tokenNotAvailableInDifferentThread() {
        setToken(xsuaaToken);

        Future<Token> tokenInOtherThread = executorService.submit(() -> SpringSecurityContext.getToken());

        assertThrows(AccessDeniedException.class, () -> tokenInOtherThread.get());
    }

    @Test
    public void clearingTokenInDifferentThreadDoesNotAffectMainThread()
            throws ExecutionException, InterruptedException {
        setToken(xsuaaToken);

        executorService.submit(() -> SpringSecurityContext.clear()).get(); // run and await other thread
        assertEquals(xsuaaToken, SpringSecurityContext.getToken());
    }

    private static void setToken(Token token) {
        HybridJwtDecoder mockJwtDecoder = Mockito.mock(HybridJwtDecoder.class);
        when(mockJwtDecoder.decode(token.getTokenValue())).thenReturn(HybridJwtDecoder.parseJwt(token));

        // initialize SpringSecurityContext with provided token
        SpringSecurityContext.init(token.getTokenValue(), mockJwtDecoder, "xsapp");
    }
}
