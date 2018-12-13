package com.sap.xs2.security.container;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

public class UserInfoTestUtil {
    public static final Date NO_EXPIRE = new Date(Long.MAX_VALUE);


    public static UserInfo createFromTemplate(String pathToTemplate, String xsAppName) throws Exception {
        String token = UserInfoTestUtil.createJwtFromTemplate(pathToTemplate);
        return createFromJwtToken(token, xsAppName);
    }

    public static UserInfo createFromClaims(JWTClaimsSet claims, String xsAppName) throws Exception {
        String token = UserInfoTestUtil.createJwtFromClaims(claims.toString());
        return createFromJwtToken(token, xsAppName);
    }

    public static UserInfo createFromJwtFile(String pathToJwt, String xsAppName) throws Exception {
        String token = IOUtils.resourceToString(pathToJwt, Charset.forName("UTF-8"));
        return createFromJwtToken(token, xsAppName);
    }

    public static UserInfo createFromJwtToken(String token, String xsAppName) throws java.text.ParseException {
        JWT parsedJwt = JWTParser.parse(token);
        JWTClaimsSet jwtClaimsSet = parsedJwt.getJWTClaimsSet();
        Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
        Jwt jwt = new Jwt(parsedJwt.getParsedString(), jwtClaimsSet.getIssueTime().toInstant(), jwtClaimsSet.getExpirationTime().toInstant(), headers, jwtClaimsSet.getClaims());
        return new UserInfo(jwt, xsAppName);
    }

    /**
     * Various methods that creates a JWT Bearer samlUserInfo.
     **/

    protected static String createJwtFromTemplate(String pathToTemplate) throws Exception {
        String claims = IOUtils.toString(UserInfoTestUtil.class.getResourceAsStream(pathToTemplate), StandardCharsets.UTF_8);
        return UserInfoTestUtil.createJwtFromClaims(claims);
    }

    protected static String createJwtFromClaims(String claims) throws Exception {
        String privateKey = IOUtils.toString(UserInfoTestUtil.class.getResourceAsStream("/privateKey.txt"), StandardCharsets.UTF_8); // PEM format
        return UserInfoTestUtil.createJwt(claims, privateKey, "legacy-samlUserInfo-key");
    }

    protected static String createJwt(String claims, String privateKey, String keyId) throws Exception {
        RsaSigner signer = new RsaSigner(privateKey);
        claims = claims.replace("$exp", "" + (System.currentTimeMillis() / 1000 + 500));

        Map<String, String> headers = new HashMap<>();
        headers.put("kid", keyId);

        org.springframework.security.jwt.Jwt jwt = JwtHelper.encode(claims, signer, headers);

        return jwt.getEncoded();
    }
}