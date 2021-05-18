package com.sap.cloud.security.xsuaa.mtls;

import com.sap.cloud.security.xsuaa.client.ClientIdentity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class SpringHttpClient {

    private SpringHttpClient() {}

    public static RestTemplate create(){
        return new RestTemplate();
    }

    public static RestTemplate create(ClientIdentity clientIdentity) throws ServiceClientException {
        HttpComponentsClientHttpRequestFactory requestFactory
                = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(HttpClient.create(clientIdentity).getCloseableHttpClient());

        return new RestTemplate(requestFactory);
    }
}
