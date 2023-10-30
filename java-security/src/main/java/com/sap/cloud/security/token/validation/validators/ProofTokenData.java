package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.x509.Certificate;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * {
 *         "consumerClientId": "d7f32a42-4185-4574-a61f-549db9f89710",
 *         "consumedServiceInstanceIds": [
 *             "5f5395bb-7dc1-4791-803e-ea7cbc3d629a"
 *         ],
 *
 *         "providerClientId": "ccaf29f2-5b94-49b4-aa3b-17c9cc08b867",
 *         "x509": [
 *             {
 *                 "dn": "CN=b/1d6a08af-582f-48b1-a133-7efae4e65f3e,L=aoxk2addh.accounts400.ondemand.com,OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84,OU=Canary,OU=SAP Cloud Platform Clients,O=SAP SE,C=DE",
 *                 "issuer": "CN=SAP Cloud Platform Client CA,OU=SAP Cloud Platform Clients,O=SAP SE,L=EU10-Canary,C=DE"
 *             }
 *         ]
 *     },
 */
public class ProofTokenData {
    private String consumerClientId;
    private List<String> consumedServiceInstanceIds = new ArrayList<>();
    private List<String[]> X509SubjectIssuerList = new ArrayList<>();

    public ProofTokenData(JSONObject jsonObject) {
        consumerClientId = jsonObject.getString("consumerClientId");
        // service instance ids
        JSONArray serviceInstanceJSONArray = jsonObject.getJSONArray("consumedServiceInstanceIds");
        serviceInstanceJSONArray.forEach(x->consumedServiceInstanceIds.add(x.toString()));

        // X509 data
        JSONArray x509JSONArray = jsonObject.getJSONArray("x509");
        x509JSONArray.forEach(x->
        {
            String dn = ((JSONObject) x).getString("dn");
            String issuer = ((JSONObject) x).getString("issuer");
            X509SubjectIssuerList.add(new String[]{dn,issuer});
        });

    }

    public String getConsumerClientId() {
        return consumerClientId;
    }

    public List<String> getConsumedServiceInstanceIds() {
        return consumedServiceInstanceIds;
    }

    public List<String[]> getX509SubjectIssuerList() {
        return X509SubjectIssuerList;
    }

    public boolean hasCertificateMapped(Certificate clientCertificate) {
        for(String[] subjectAndIssuer: getX509SubjectIssuerList()){
            if(clientCertificate.getSubjectDN(X500Principal.RFC2253).equals(subjectAndIssuer[0]) &&
                    clientCertificate.getIssuerDN(X500Principal.RFC2253).equals(subjectAndIssuer[1])){
                return true;
            }
        }
        return false;
    }
}
