package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.client.DefaultHttpClientFactory;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

public class ProofTokenDataRetriever implements Runnable{

    private static final Logger LOGGER = LoggerFactory.getLogger(ProofTokenDataRetriever.class);
    public static final int POLL_TIME = 1000 * 60; // poll time in ms
    private Map<String, ProofTokenData> proofTokenDataMap = new HashMap<>();
    private ClientIdentity clientIdentity = null;
    private String proofTokenEndpoint = null;

    private Thread backgroundThread;
    private boolean doRun = true;

    private final CloseableHttpClient httpClient;

    public ProofTokenDataRetriever(OAuth2ServiceConfiguration oAuth2ServiceConfiguration, CloseableHttpClient httpClient){
        clientIdentity = oAuth2ServiceConfiguration.getClientIdentity();
        proofTokenEndpoint = oAuth2ServiceConfiguration.getProperty("prooftoken_url");
        this.httpClient = httpClient;
        try {
            readProofTokenData();
        } catch (Exception e) {
            LOGGER.warn("Failed retrieving proof token data from {} due to ",proofTokenEndpoint,e.getMessage(),e);
        }
        backgroundThread = new Thread(this);
        backgroundThread.start();
    }
    public ProofTokenDataRetriever(OAuth2ServiceConfiguration oAuth2ServiceConfiguration){
        this(oAuth2ServiceConfiguration,  new DefaultHttpClientFactory().createClient(oAuth2ServiceConfiguration.getClientIdentity()));
    }

    public ProofTokenData getDataByTokenAndCertificate(Token token, com.sap.cloud.security.x509.Certificate clientCertificate) {
        ProofTokenData proofTokenData = proofTokenDataMap.get(token.getClaimAsString("azp"));
        if(proofTokenData!=null && proofTokenData.hasCertificateMapped(clientCertificate))
        {
            return proofTokenData;
        }
        else{
            return null;
        }
    }
    protected int setData(String jsonData)
    {
        Map<String,ProofTokenData> proofTokenDataMap = new HashMap<>();
        JSONArray rootArray = new JSONArray(jsonData);
        for(int i=0;i<rootArray.length();i++) {
            ProofTokenData proofTokenData = new ProofTokenData(rootArray.getJSONObject(i));
            proofTokenDataMap.put(proofTokenData.getConsumerClientId(),proofTokenData);
        }
        this.proofTokenDataMap = proofTokenDataMap;
        return proofTokenDataMap.size();
    }

    public void stop(){
         doRun = false;
    }
    @Override
    public void run() {
        while(doRun){
            try{
                readProofTokenData();
                Thread.sleep(POLL_TIME); // every minute
            } catch (IOException | InterruptedException e) {
                LOGGER.warn("Failed retrieving proof token data from {} due to ",proofTokenEndpoint,e.getMessage(),e);
                try {
                    Thread.sleep(1000*60);
                } catch (InterruptedException ex) {
                   LOGGER.debug("interrupted",ex);
                }
            }
        }
    }

    private void readProofTokenData() throws IOException {
        HttpGet proofTokenEndpointRequest = new HttpGet(proofTokenEndpoint);
        proofTokenEndpointRequest.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
        CloseableHttpResponse proofTokenEndpointResponse = httpClient.execute(proofTokenEndpointRequest);
        if( proofTokenEndpointResponse.getStatusLine().getStatusCode() == 200){
            ByteArrayOutputStream responseDataStream = new ByteArrayOutputStream();
            proofTokenEndpointResponse.getEntity().writeTo(responseDataStream);
           String responseDataString = responseDataStream.toString(Charset.forName("UTF-8"));
            int count = setData(responseDataString);
            LOGGER.info("Successfully retrieved {}  proof token entries from {}",count, proofTokenEndpoint);
        }
    }
}
