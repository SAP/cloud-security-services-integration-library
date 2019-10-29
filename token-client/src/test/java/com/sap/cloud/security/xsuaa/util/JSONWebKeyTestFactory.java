package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeyImpl;

public class JSONWebKeyTestFactory {

	private static final String PUBLIC_KEY = "----BEGIN PUBLIC KEY-----\\n"
			+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgG\\n"
			+ "WFgVWQX6MHnadYk3zHZ5PIPeDY3ApaSGpMEiVwn1cT6KUVHMLHcmz1gsNy74pCnm\\n"
			+ "Ca22W7J3BoZulzR0A37ayMVrRHh3nffgySk8u581l02bvbcpab3e3EotSN5LixGT\\n"
			+ "1VWZvDbalXf6n5kq459NWL6ZzkEs20MrOEk5cLdnsigTQUHSKIQ5TpldyDkJMm2z\\n"
			+ "wOlrB2R984+QdlDFmoVH7Yaujxr2g0Z96u7W9Imik6wTiFc8W7eUXfhPGn7reVLq\\n"
			+ "1/5o2Nz0Jx0ejFHDwTGncs+k1RBS6DbpTOMr9tkJEc3ZsX3Ft4OtqCkRXI5hUma+\\n"
			+ "HwIDAQAB\\n"
			+ "-----END PUBLIC KEY-----";
	private static final String ALG = "RS256";
	private static final JSONWebKey.Type KEY_TYPE = JSONWebKey.Type.valueOf("RSA");
	private static final String KEY_ID = "key-id-1";

	public static JSONWebKey create() {
		return new JSONWebKeyImpl(KEY_TYPE, KEY_ID, ALG, PUBLIC_KEY);
	}
}
