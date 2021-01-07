package sample.spring.xsuaa.util;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

// https://docs.spring.io/autorepo/docs/spring-security/4.0.0.RELEASE/reference/html/test-mockmvc.html#test-mockmvc-smmrpp
public final class MockBearerTokenRequestPostProcessor {

    private MockBearerTokenRequestPostProcessor() {
    }

    public static RequestPostProcessor bearerToken(String token) {
        return new BearerTokenRequestPostProcessor(token);
    }

    static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
        private final String token;

        public BearerTokenRequestPostProcessor(String token) {
            this.token = token;
        }

        @Override
        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + this.token);
            return request;
        }
    }
}
