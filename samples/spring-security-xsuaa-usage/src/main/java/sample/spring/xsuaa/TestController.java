/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.spring.xsuaa;

import java.net.URI;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sap.cloud.security.xsuaa.XsuaaServiceBindings;
import com.sap.cloud.security.xsuaa.XsuaaServiceBindings.XsuaaBindingInfo;
import com.sap.cloud.security.xsuaa.XsuaaToken;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

import sample.spring.xsuaa.datalayer.DataLayer;

@RestController
public class TestController {
    
    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    /**
     * The injected factory for XSUAA token flows.
     */
    @Autowired
    private XsuaaTokenFlows xsuaaTokenFlows;
    
    /**
     * The injected XSUAA service binding information from environment.
     */
    @Autowired
    private XsuaaServiceBindings xsuaaServiceBindings;
    
    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    @Autowired
    private DataLayer dataLayer;
    
    /**
     * Returns the address of the address service.
     * Uses a JWT retrieved from the security context of Spring Security.
     * @param jwt the JWT from the request injected by Spring Security.
     * @return the requested address.
     * @throws Exception in case of an internal error.
     */
    @RequestMapping(value = "/v1/address", method = RequestMethod.GET)
    public String sayHello(@AuthenticationPrincipal Jwt jwt) throws Exception {
        
        logger.info("Got the JWT: " + jwt);
        
        // You can always use the XSUAAToken as a wrapper, too.
        // In case you are using a standard Spring Security Jwt 
        // and did not exchange the underlying implementation, wrapping
        // it with XSUAAToken will provide you more convenience accessing
        // custom XSUAA token claims.
        XsuaaToken token = new XsuaaToken(jwt);
        logger.info(token.toString());
                
        return "Hello Jwt-Protected World!";
    }
    
    /**
     * An endpoint showing how to use Spring method security.
     * Only if the request principal has the given scope will the 
     * method be called. Otherwise a 403 error will be returned.
     */
    @RequestMapping(value = "/v1/method", method = RequestMethod.GET)
    @PreAuthorize("hasAuthority('SCOPE_read_resource')")
    public String callMethodRemotely() {
        return "Method called!";
    }
    
    /**
     * More advanced showcase for global method security.
     * The {@link DataLayer} interface uses annotated methods
     * and when the {@link DataLayer} gets injected as a bean
     * Spring Security wraps it with a security-enforcing wrapper.
     * The result is, that the {@link DataLayer#readData()} method
     * will only be called if the proper scopes are available.
     * 
     * @see {@link DataLayer}.
     * @return the data read from the {@link DataLayer} or fails
     * with an access denied error.
     */
    @RequestMapping(value = "/v1/readData", method = RequestMethod.GET)
    public String readFromDataLayer() {
        return dataLayer.readData();
    }
    
    /**
     * Write case showing method level security.
     */
    @RequestMapping(value = "/v1/writeData", method = RequestMethod.POST)
    public void writeToDataLayer() {
        dataLayer.writeData("Spring Rocks!");
    }
    
    /**
     * REST endpoint showing how to fetch a Client Credentials Token from XSUAA using the 
     * XsuaaTokenFlows bean injected by Spring and exposed by the (new) XSUAA client library 
     * implementation. 
     * @param jwt - the Jwt as a result of authentication.
     * @return the Client Credentials Token fetched from XSUAA. Don't do this in production!
     * @throws Exception in case of any errors.
     */
    @RequestMapping(value = "/v1/clientCredentialsToken", method = RequestMethod.GET)
    public Jwt fetchClientCredentialsToken(@AuthenticationPrincipal Jwt jwt) throws Exception { 
        
        Map<String, XsuaaBindingInfo> bindings = xsuaaServiceBindings.getXsuaaBindingInformation();
        
        XsuaaBindingInfo xsuaaBindingInfo = bindings.get("xsuaa-authentication"); 
        
        String baseUrl = xsuaaBindingInfo.getCredentials().getBaseUrl();
        String clientId = xsuaaBindingInfo.getCredentials().getClientId();
        String clientSecret = xsuaaBindingInfo.getCredentials().getClientSecret();
        
        Jwt ccfToken = xsuaaTokenFlows.clientCredentialsFlow(URI.create(baseUrl))
                .client(clientId)
                .secret(clientSecret)
                .execute();
 
        logger.info("CCF Token: {}", ccfToken.getTokenValue());
        
        return ccfToken;
    }
    
    /**
     * Prints the XSUAA service instance binding information from environment.
     * @param jwt - the Jwt as a result of authentication.
     * @return the XSUAA service instance binding information from environment.
     * @throws Exception in case of any errors.
     */
    @RequestMapping(value = "/v1/printXsuaaBindingInformation", method = RequestMethod.GET)
    public String printXsuaaServiceBindingsInformation(@AuthenticationPrincipal Jwt jwt) throws Exception { 
        
        Map<String, XsuaaBindingInfo> bindings = xsuaaServiceBindings.getXsuaaBindingInformation();
        
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(bindings);
        logger.info("Parsed XSUAA Configurations from Environment: ");
        logger.info(json);
        return json;
    }
}
