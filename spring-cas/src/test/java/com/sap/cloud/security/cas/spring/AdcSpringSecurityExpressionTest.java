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

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AdcSpringSecurityExpressionTest {

	private static final String USER_ID = "theUserId";
	private static final String ZONE_ID = "theZoneId";
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
				.contains("theResource", "theAction", "theAttribute", "theValue", USER_ID, ZONE_ID);
	}

	@Test
	void forAction_createsServiceRequest() {
		cut.forAction("theAction", "theAttribute=theValue");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theAction", "theAttribute", "theValue", USER_ID, ZONE_ID);
	}

	@Test
	void forResource_createsServiceRequest() {
		cut.forResource("theResource", "attributeKey=attributeValue");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theResource", "attributeKey", "attributeValue", USER_ID, ZONE_ID);
	}

	@Test
	void forResourceWithoutAttributes_createsServiceRequest() {
		cut.forResource("theResource");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theResource", USER_ID, ZONE_ID);
	}

	@Test
	void forActioWithoutAttributes_createsServiceRequest() {
		cut.forAction("theAction");

		AdcServiceRequest request = verifyIsUserAuthorizedCalled();
		assertThat(request).isNotNull();
		assertThat(request.asInputJson()).contains("theAction", USER_ID, ZONE_ID);
	}

	private AdcServiceRequest verifyIsUserAuthorizedCalled() {
		verify(adcService).isUserAuthorized(adcServiceRequestArgumentCaptor.capture());
		return adcServiceRequestArgumentCaptor.getValue();
	}

	private AdcServiceResponse createResponse(boolean value) {
		return new AdcServiceResponseDefault(String.format("{\"result\": \"%s\"}", value));
	}

	private Authentication createAuthentication() {
		DefaultOAuth2AuthenticatedPrincipal authenticatedPrincipal = new DefaultOAuth2AuthenticatedPrincipal(
				"theUserId", Maps.newHashMap("zone_uuid", ZONE_ID), Collections.emptyList());
		return new TestingAuthenticationToken(authenticatedPrincipal, null);
	}
}