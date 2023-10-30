package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.x509.Certificate;
import org.apache.http.HttpEntity;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicStatusLine;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ProofTokenDataRetrieverTest {

    String proofTokenData = "[\n" +
            "    {\n" +
            "        \"consumerClientId\": \"2d640305-5c07-40e8-9a18-92747754b099\",\n" +
            "        \"consumedServiceInstanceIds\": [\n" +
            "            \"01c8b1b7-3b0a-4579-b43d-efad0708275e\"\n" +
            "        ],\n" +
            "        \"consumedServiceInstances\": [\n" +
            "            {\n" +
            "                \"id\": \"01c8b1b7-3b0a-4579-b43d-efad0708275e\",\n" +
            "                \"plan\": {\n" +
            "                    \"name\": \"application\"\n" +
            "                }\n" +
            "            }\n" +
            "        ],\n" +
            "        \"x509\": [],\n" +
            "        \"providerClientId\": \"ccaf29f2-5b94-49b4-aa3b-17c9cc08b867\"\n" +
            "    },\n" +
            "    {\n" +
            "        \"consumerClientId\": \"d7f32a42-4185-4574-a61f-549db9f89710\",\n" +
            "        \"consumedServiceInstanceIds\": [\n" +
            "            \"5f5395bb-7dc1-4791-803e-ea7cbc3d629a\"\n" +
            "        ],\n" +
            "        \"consumedServiceInstances\": [\n" +
            "            {\n" +
            "                \"id\": \"5f5395bb-7dc1-4791-803e-ea7cbc3d629a\",\n" +
            "                \"plan\": {\n" +
            "                    \"name\": \"application\"\n" +
            "                }\n" +
            "            }\n" +
            "        ],\n" +
            "        \"providerClientId\": \"ccaf29f2-5b94-49b4-aa3b-17c9cc08b867\",\n" +
            "        \"x509\": [\n" +
            "            {\n" +
            "                \"dn\": \"CN=b/1d6a08af-582f-48b1-a133-7efae4e65f3e,L=aoxk2addh.accounts400.ondemand.com,OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84,OU=Canary,OU=SAP Cloud Platform Clients,O=SAP SE,C=DE\",\n" +
            "                \"issuer\": \"CN=SAP Cloud Platform Client CA,OU=SAP Cloud Platform Clients,O=SAP SE,L=EU10-Canary,C=DE\"\n" +
            "            }\n" +
            "        ]\n" +
            "    },\n" +
            "]";

    @Test
    public void getDataByTokenAndCertificate() throws IOException, InterruptedException {
        OAuth2ServiceConfiguration oauthServiceConfiguration = OAuth2ServiceConfigurationBuilder.forService(Service.IAS)
                .withClientId("11-22")
                .withProperty("prooftoken_url", "https://eu-osb.accounts400.ondemand.com/sap/cp-kernel/identity/v1/prooftoken/bd4cc25a-0abe-4718-a6b6-6997617b85a1/v2")
                .build();

        CloseableHttpClient httpClient = getHttpClientFactory().createClient(oauthServiceConfiguration.getClientIdentity());
        ProofTokenDataRetriever proofTokenDataRetriever = new ProofTokenDataRetriever(oauthServiceConfiguration, httpClient);
        Thread.sleep(2000);

        // test tokens
        Token tokenExists = Mockito.mock(Token.class);
        when(tokenExists.getClaimAsString("azp")).thenReturn("d7f32a42-4185-4574-a61f-549db9f89710");
        Token tokenNotExists = Mockito.mock(Token.class);
        when(tokenNotExists.getClaimAsString("azp")).thenReturn("e7f32a42-4185-4574-a61f-549db9f89710");

        // test certificates
        Certificate clientCertExists = Mockito.mock(Certificate.class);
        when(clientCertExists.getSubjectDN(X500Principal.RFC2253)).thenReturn("CN=b/1d6a08af-582f-48b1-a133-7efae4e65f3e,L=aoxk2addh.accounts400.ondemand.com,OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84,OU=Canary,OU=SAP Cloud Platform Clients,O=SAP SE,C=DE");
        when(clientCertExists.getIssuerDN(X500Principal.RFC2253)).thenReturn("CN=SAP Cloud Platform Client CA,OU=SAP Cloud Platform Clients,O=SAP SE,L=EU10-Canary,C=DE");

        Certificate clientCertNotExists = Mockito.mock(Certificate.class);
        when(clientCertNotExists.getSubjectDN(X500Principal.RFC2253)).thenReturn("CN=c/1d6a08af-582f-48b1-a133-7efae4e65f3e,L=aoxk2addh.accounts400.ondemand.com,OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84,OU=Canary,OU=SAP Cloud Platform Clients,O=SAP SE,C=DE");
        when(clientCertNotExists.getIssuerDN(X500Principal.RFC2253)).thenReturn("CN=SAP Cloud Platform Client CA,OU=SAP Cloud Platform Clients,O=SAP SE,L=EU10-Canary,C=DE");

        // test ok
        ProofTokenData proofTokenEntry = proofTokenDataRetriever.getDataByTokenAndCertificate(tokenExists, clientCertExists);
        Assert.assertNotNull(proofTokenEntry);
        Assert.assertEquals("d7f32a42-4185-4574-a61f-549db9f89710", proofTokenEntry.getConsumerClientId());

        // test all combinations
        Assert.assertNotNull(proofTokenDataRetriever.getDataByTokenAndCertificate(tokenExists, clientCertExists));
        Assert.assertNull(proofTokenDataRetriever.getDataByTokenAndCertificate(tokenExists, clientCertNotExists));
        Assert.assertNull(proofTokenDataRetriever.getDataByTokenAndCertificate(tokenNotExists, clientCertExists));
        Assert.assertNull(proofTokenDataRetriever.getDataByTokenAndCertificate(tokenNotExists, clientCertExists));

    }

    private HttpClientFactory getHttpClientFactory() throws IOException {
        HttpClientFactory clientFactory = Mockito.mock(HttpClientFactory.class);
        CloseableHttpClient closeableHttpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
        when(response.getEntity()).thenAnswer(new Answer<BasicHttpEntity>() {
            @Override
            public BasicHttpEntity answer(InvocationOnMock invocationOnMock) throws Throwable {
                BasicHttpEntity entity = new BasicHttpEntity();
                entity.setContent(new ByteArrayInputStream(proofTokenData.getBytes()));
                return entity;
            }
        });
        when(response.getStatusLine()).thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 200, ""));
        when(closeableHttpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
        when(clientFactory.createClient(any())).thenReturn(closeableHttpClient);
        return clientFactory;
    }


    @Test
    public void setData() {
    }
}