package com.sap.cloud.security.xsuaa;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

/**
 * An authentication converter that replaces the ugly XSAppName's of scopes 
 * in the JWT with an application-defined prefix.
 * If the JWT contains for only a single application then the XSAppName prefix can
 * actually be removed - this will be performed by the default constructor.
 * 
 * If there are scopes for multiple applications in the JWT token, then a prefix is
 * required to uniquely identify the scopes for different applications.
 * Use the map-argument constructor in that case and provide a mapping between
 * XSAppName prefixes and the human-readable replacements. E.g.:
 * 
 * <pre> 
 * Converter<Jwt, AbstractAuthenticationToken> grantedAuthoritiesExtractor() {
 * 
 *   Map<String, String> replacements = new HashMap<>();
 *   replacements.put(my-application-demo!t12291, "my.");
 *   replacements.put(foreign-app!b12291, "foreign.");
 *   
 *   return new XsAppNameReplacingAuthoritiesExtractor(replacements);
 * }
 * </pre> 
 * 
 * You can then use the authorities extractor in your WebSecurityConfiguration like this:
 * 
 * <pre>
 * protected void configure(HttpSecurity http) throws Exception {
 *   http
 *       .sessionManagement()
 *           .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
 *       .and()
 *           .authorizeRequests()
 *               .antMatchers("/actuator/**").permitAll()
 *               .antMatchers("/v1/address").hasAuthority("SCOPE_my.Read")
 *               .antMatchers("/v1/somethingForeign").hasAuthority("SCOPE_foreign.Read")
 *               .anyRequest().authenticated()
 *       .and()
 *           .oauth2ResourceServer()
 *               .jwt()
 *               .jwtAuthenticationConverter(grantedAuthoritiesExtractor());
 * </pre>
 * 
 * The default constructor will use a regular expression to remove all XSAppName prefixes from
 * JWT scopes.
 * 
 */
public class XsAppNameReplacingAuthoritiesExtractor extends JwtAuthenticationConverter implements AuthoritiesExtractor {
    private static final String SCOPE_PREFIX = "SCOPE_";
    private Map<String, String> replacementStrings;
    
    /**
     * Creates a new instance that (using a regular expression) will remove XSAppName
     * prefixes from JWT scopes. Use this only if your JWT contains only scopes of
     * the same XSApp.
     */
    public XsAppNameReplacingAuthoritiesExtractor() {
        replacementStrings = new HashMap<String, String>();
        replacementStrings.put(".*![ibtu].*\\.", "");
    }
    
    /**
     * Creates a new instance that replaces all occurrences (given as keys) in {@code replacementStrings} 
     * with application-defined values (given as values in {@code replacementStrings}.
     * @param replacementStrings the mapping of XSAppNames to replacements.
     */
    public XsAppNameReplacingAuthoritiesExtractor(Map<String, String> replacementStrings) {
        if(replacementStrings == null)
            throw new IllegalArgumentException("Error! Replacement Strings map must not be null");
        
        this.replacementStrings = replacementStrings;
    }
    
    @Override
    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<String> scopes = jwt.getClaimAsStringList("scope");
        List<String> authorities = new ArrayList<>(scopes.size());
        
        for(String scope : scopes) {
            for (Entry<String, String> entry : replacementStrings.entrySet())
            {
                authorities.add(SCOPE_PREFIX + scope.replaceAll(entry.getKey(), entry.getValue()));
            }
        }
        
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities(Jwt jwt) {
        return extractAuthorities(jwt);
    }
}
