package com.sap.cloud.security.xsuaa.jwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface DecodedJwt {

	String getHeader();

	@Nullable
	String getHeaderValue(@Nonnull String name);

	String getPayload();

	@Nullable // TODO getClaimByName?
	String getPayloadValue(@Nonnull String name);

	String getSignature();

	String getEncodedToken();
}
