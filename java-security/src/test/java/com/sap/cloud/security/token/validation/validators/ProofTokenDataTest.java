package com.sap.cloud.security.token.validation.validators;

import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class ProofTokenDataTest {

    String testJson = "{\n" +
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
            "    }";
    @Test
    public void testParsing() {
        // parse data
        JSONObject jsonObject = new JSONObject(testJson);
        ProofTokenData proofTokenData = new ProofTokenData(jsonObject);

        // validate data
        Assert.assertEquals("d7f32a42-4185-4574-a61f-549db9f89710",proofTokenData.getConsumerClientId());
        Assert.assertEquals(Arrays.asList("5f5395bb-7dc1-4791-803e-ea7cbc3d629a"),proofTokenData.getConsumedServiceInstanceIds());
        Assert.assertEquals(1,proofTokenData.getX509SubjectIssuerList().size());
        Assert.assertEquals("CN=b/1d6a08af-582f-48b1-a133-7efae4e65f3e,L=aoxk2addh.accounts400.ondemand.com,OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84,OU=Canary,OU=SAP Cloud Platform Clients,O=SAP SE,C=DE",proofTokenData.getX509SubjectIssuerList().get(0)[0]);
        Assert.assertEquals("CN=SAP Cloud Platform Client CA,OU=SAP Cloud Platform Clients,O=SAP SE,L=EU10-Canary,C=DE",proofTokenData.getX509SubjectIssuerList().get(0)[1]);

    }
}