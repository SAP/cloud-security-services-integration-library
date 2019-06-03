package sample.spring.xsuaa;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsAppNameReplacingAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.XsuaaTokenConverter;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Pick either of these to try things out.
        //configure_ExchangingStandardJwtForXSUAAToken(http);
        configure_ExchangingStandardJwtForXSUAAToken_And_NicerAuthorityNames(http);
        //configure_UsingStandardJWT_And_NicerAuthorityNames(http);
        //configure_UsingStandardJWT(http);
    }
     
    /**
     * Configures Spring Security to exchange the standard Jwt for a custom XSUAAToken implementation.
     * This allows you to reference the XSUAAToken in REST controller methods using 
     * {@code @AuthenticationPrincipal XSUAAToken token}. I.e. you do not have to cast tokens.
     * You can, however, also still use {@code @AuthenticationPrincipal Jwt jwt} since XSUAAToken is a
     * direct descendant of Spring's Jwt class.  
     * 
     * Scopes will be mapped to authorities in the standard Spring Security way. No modification
     * of scope names is performed (except for Spring Securities addition of the SCOPE_ prefix).
     * 
     * @param http
     * @throws Exception
     */
    private void configure_ExchangingStandardJwtForXSUAAToken(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource")
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                       .jwtAuthenticationConverter(jwtToXsuaaTokenConverter());
                     // .decoder(decoder)                                             // see: https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver-decoder-dsl
                     // .jwkSetUri(uri)                                               // see: https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver-jwkseturi-dsl
                     // .jwtAuthenticationConverter(getJwtAuthenticationConverter()); // see: https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver-authorization-extraction
        // @formatter:on 
    }
    
    /**
     * Configures Spring Security to exchange the standard Jwt for a custom XSUAAToken implementation.
     * This allows you to reference the XSUAAToken in REST controller methods using 
     * {@code @AuthenticationPrincipal XSUAAToken token}. I.e. you do not have to cast tokens.
     * You can, however, also still use {@code @AuthenticationPrincipal Jwt jwt} since XSUAAToken is a
     * direct descendant of Spring's Jwt class.
     * 
     * Scopes will be mapped to authorities in a custom way replacing the XsAppName in the scopes for empty
     * strings. This allows checking a scope of {@code spring-netflix-demo!t12291.Read} simply by calling
     * {@code hasAuthority("SCOPE_Read")}.
     * 
     * Note that replacing the XsAppName can be customized so, you could add your own replacement string 
     * (other than the empty string) for it.
     * 
     * @param http
     * @throws Exception
     */
    private void configure_ExchangingStandardJwtForXSUAAToken_And_NicerAuthorityNames(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the jwtToXsuaaTokenConverterReplacingXSAppName() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(jwtToXsuaaTokenConverterReplacingXSAppName());
        // @formatter:on 
    }
    
    /**
     * Configures Spring Security to use the standard Spring Security Jwt implementation, but maps the
     * Jwt's authorities in a custom way replacing the XsAppName in the scopes for empty
     * strings. This allows checking a scope of {@code spring-netflix-demo!t12291.Read} simply by calling
     * {@code hasAuthority("SCOPE_Read")}.
     * 
     * Note that replacing the XsAppName can be customized so, you could add your own replacement string 
     * (other than the empty string) for it.
     * 
     * You will be able to refer to the Jwt in REST controllers only by {@code @AuthenticationPrincipal Jwt jwt}
     * not {@code @AuthenticationPrincipal XSUAAToken token}. The latter will throw a runtime cast exception.
     * 
     * @param http
     * @throws Exception
     */
    private void configure_UsingStandardJWT_And_NicerAuthorityNames(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the xsAppNameReplacingAuthoritiesExtractor() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(xsAppNameReplacingAuthoritiesExtractor());
        // @formatter:on 
    }
    
    /**
     * Configures Spring Security to use the standard Spring Security Jwt as it comes out of the box.
     * No scope / authority adaptations are performed other than the default Spring Security ones (i.e.
     * adding the SCOPE_ prefix).
     * 
     * You will be able to refer to the Jwt in REST controllers only by {@code @AuthenticationPrincipal Jwt jwt}
     * not {@code @AuthenticationPrincipal XSUAAToken token}. The latter will throw a runtime cast exception.
     * 
     * @param http
     * @throws Exception
     */
    private void configure_UsingStandardJWT(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/actuator/**").permitAll()
                    .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the xsAppNameReplacingAuthoritiesExtractor() that was added using .jwtAuthenticationConverter().
                    .anyRequest().authenticated()
            .and()
                .oauth2ResourceServer()
                    .jwt();
        // @formatter:on 
    }
    
    /**
     * A JWT token's scopes are by default converted into Spring Security Authorities and prefixed with "SCOPE_".
     * You can then use these authorities in Spring Security Expression Language (SpEL) terms or 
     * in the .hasAuthority(...) methods of the WebSecurityConfigurationAdapter.
     * 
     * You can also override the default mapping like this.
     * It basically extracts the scopes from the JWT and strips the XSUAA XSAPPNAME and tenant host pattern.
     * As a result you can just use ".hasAuthority("SCOPE_Read")" rather than "hasAuthority("SCOPE_spring-netflix-demo!t12291.Read")"
     * @return the authorities extractor used to map / extract JWT scopes.
     */
    Converter<Jwt, AbstractAuthenticationToken> xsAppNameReplacingAuthoritiesExtractor() {
        return new XsAppNameReplacingAuthoritiesExtractor();
    }
    
    
    /**
     * Converts a Jwt token from Spring Security to an XSUAA token.
     * 
     * Our XSUAA token inherits from Jwt, so applications don't lose any
     * standard Jwt functionality, but gain some more convenience.
     * In REST endpoints you can use {@code @AuthenticationPrincipal Jwt jwt}
     * or {@code @AuthenticationPrincipal XSUAAToken token} interchangeably.
     * @return the token converter.
     */
    Converter<Jwt, AbstractAuthenticationToken> jwtToXsuaaTokenConverter() {
        return new XsuaaTokenConverter();
    } 
    
    /**
     * Converts a Jwt token from Spring Security to an XSUAA token.
     * Also replaces the XSAppName in the scopes when mapping them to 
     * granted authorities.
     * 
     * Our XSUAA token inherits from Jwt, so applications don't lose any
     * standard Jwt functionality, but gain some more convenience.
     * In REST endpoints you can use {@code @AuthenticationPrincipal Jwt jwt}
     * or {@code @AuthenticationPrincipal XSUAAToken token} interchangeably.
     * @return the token converter.
     */
    Converter<Jwt, AbstractAuthenticationToken> jwtToXsuaaTokenConverterReplacingXSAppName() {
        return new XsuaaTokenConverter(new XsAppNameReplacingAuthoritiesExtractor());
    }   
}

