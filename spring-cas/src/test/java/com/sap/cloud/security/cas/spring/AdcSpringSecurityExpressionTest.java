package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceRequest;
import com.sap.cloud.security.cas.client.AdcServiceResponse;
import com.sap.cloud.security.cas.client.AdcServiceResponseDefault;
import org.assertj.core.util.Maps;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.cas.spring.AdcSpringSecurityExpression.USER_UUID_KEY;
import static com.sap.cloud.security.cas.spring.AdcSpringSecurityExpression.ZONE_UUID_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AdcSpringSecurityExpressionTest {

	private static final String USER_UUID = "theUserId";
	private static final String ZONE_UUID = "theZoneId";
	private AdcSpringSecurityExpression cut;
	private AdcService adcService;
	private ArgumentCaptor<AdcServiceRequest> adcServiceRequestArgumentCaptor;

	@BeforeEach
	void setUp() {
		adcService = Mockito.mock(AdcService.class);
		adcServiceRequestArgumentCaptor = ArgumentCaptor.forClass(AdcServiceRequest.class);
		when(adcService.isUserAuthorized(any())).thenReturn(createResponse(true));
		cut = new AdcSpringSecurityExpression(createAuthentication()).withAdcService(adcService);
	}

	@Test
	void forResourceAction_isAuthorized() {
		AdcServiceResponse response = createResponse(true);
		when(adcService.isUserAuthorized(any())).thenReturn(response);

		boolean authorized = cut.forResourceAction("resource", "action", "attribute=value");

		assertThat(authorized).isTrue();
	}

	@Test
	void forResourceAction_isNotAuthorized() {
		AdcServiceResponse response = createResponse(false);
		when(adcService.isUserAuthorized(any())).thenReturn(response);

		boolean authorized = cut.forResourceAction("resource", "action", "attribute=value");

		assertThat(authorized).isFalse();
	}

	@Test
	void forResourceAction_serviceError_isNotAuthorized() {
		when(adcService.isUserAuthorized(any())).thenThrow(new IllegalStateException());

		boolean authorized = cut.forResourceAction("theResource", "theAction", "theAttribute=theValue");

		assertThat(authorized).isFalse();
	}

	@Test
	void forResourceAction_createsServiceRequest() {
		cut.forResourceAction("theResource", "theAction", "theAttribute=theValue");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson())
				.contains("theResource", "theAction", "theAttribute", "theValue", USER_UUID, ZONE_UUID);
	}

	@Test
	void forAction_createsServiceRequest() {
		cut.forAction("theAction", "theAttribute=theValue");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theAction", "theAttribute", "theValue", USER_UUID, ZONE_UUID);
	}

	@Test
	void forResource_createsServiceRequest() {
		cut.forResource("theResource", "attributeKey=attributeValue");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theResource", "attributeKey", "attributeValue", USER_UUID,
				ZONE_UUID);
	}

	@Test
	void forResourceWithoutAttributes_createsServiceRequest() {
		cut.forResource("theResource");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theResource", USER_UUID, ZONE_UUID);
	}

	@Test
	void forActionWithoutAttributes_createsServiceRequest() {
		cut.forAction("theAction");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theAction", USER_UUID, ZONE_UUID);
	}

	@Test
	void forResourceAction_withJwtAuthenticationToken_createsServiceRequest() {
		JwtAuthenticationToken authentication = Mockito.mock(JwtAuthenticationToken.class);
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(USER_UUID_KEY, USER_UUID);
		attributes.put(ZONE_UUID_KEY, ZONE_UUID);
		when(authentication.getTokenAttributes()).thenReturn(attributes);
		cut = new AdcSpringSecurityExpression(authentication).withAdcService(adcService);

		cut.forResourceAction("theResource", "theAction", "theAttribute=theValue");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson())
				.contains("theResource", "theAction", "theAttribute", "theValue", USER_UUID, ZONE_UUID);
	}

	private AdcServiceRequest verifyIsUserAuthorizedCalled() {
		verify(adcService).isUserAuthorized(adcServiceRequestArgumentCaptor.capture());
		return adcServiceRequestArgumentCaptor.getValue();
	}

	private AdcServiceResponse createResponse(boolean value) {
		return new AdcServiceResponseDefault(String.format("{\"result\": \"%s\"}", value));
	}

	private Authentication createAuthentication() {
		Map<String, Object> attributes = Maps.newHashMap(ZONE_UUID_KEY, ZONE_UUID);
		attributes.put(USER_UUID_KEY, USER_UUID);
		DefaultOAuth2AuthenticatedPrincipal authenticatedPrincipal = new DefaultOAuth2AuthenticatedPrincipal(
				"", attributes, Collections.emptyList());
		return new TestingAuthenticationToken(authenticatedPrincipal, null);
	}
}