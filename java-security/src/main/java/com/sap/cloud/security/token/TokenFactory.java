package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER;

/**
 * Creates a {@link Token} instance. Supports Jwt tokens from IAS and XSUAA identity service.
 */
public class TokenFactory {

    private TokenFactory() {
        // use the factory method instead
    }

    /**
     * Determines whether the JWT token is issued by XSUAA identity service, and creates a Token for it.
     *
     * @param encodedToken the encoded token
     * @return the new token instance
     */
    public static Token create(String encodedToken) {
        DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(encodedToken);

        if(isXsuaaToken(decodedJwt)) {
            return new XsuaaToken(decodedJwt);
        }
        return new SapIdToken(decodedJwt);
    }

    /**
     * Determines if the provided decoded jwt token is issued by the Xsuaa idenity service.
     *
     * @param decodedJwt jwt to be checked
     * @return true if provided token is a XSUAA token
     */
    private static boolean isXsuaaToken(DecodedJwt decodedJwt) {
        String jwtPayload = decodedJwt.getPayload().toLowerCase();
        return jwtPayload.contains(EXTERNAL_ATTRIBUTE)
                && jwtPayload.contains(EXTERNAL_ATTRIBUTE_ENHANCER)
                && jwtPayload.contains("xsuaa");

    }
}
