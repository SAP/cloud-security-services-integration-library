package com.sap.cloud.security.xsuaa;


import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.util.StringUtils;

public class XsuaaServicesParser {

	private final Log logger = LogFactory.getLog(XsuaaServicesParser.class);

	private static final String TAGS = "tags";
	private static final String CREDENTIALS = "credentials";
	private static final String VCAP_SERVICES = "VCAP_SERVICES";
	private static final String XSUAA_TAG = "xsuaa";

	private static String vcapServices;

	public XsuaaServicesParser() {
		vcapServices = System.getenv().get(VCAP_SERVICES);
        if (StringUtils.isEmpty(vcapServices)) {
			logger.warn("Cannot find environment " + VCAP_SERVICES);
        }
	}

	public XsuaaServicesParser(InputStream is ) throws IOException {
		vcapServices = IOUtils.toString(is,Charsets.toCharset("utf-8"));
        if (StringUtils.isEmpty(vcapServices)) {
			logger.warn("Cannot find environment " + VCAP_SERVICES);
        }
	}
	/**
	 * @param name
	 *            the attribute name
	 * @return associated value to given tag name or null if attribute not found
	 */
	public Optional<String> getAttribute(String name) {

		if (StringUtils.isEmpty(vcapServices)) {
			return Optional.empty();
		}

		try {
			JSONObject vcap = new JSONObject(vcapServices);
			JSONObject xsuaaBinding = searchXSuaaBinding(vcap);

			if (Objects.nonNull(xsuaaBinding) && xsuaaBinding.has(CREDENTIALS)) {
				JSONObject credentials = xsuaaBinding.getJSONObject(CREDENTIALS);
				return Optional.ofNullable(credentials.getString(name));
			}
		} catch (JSONException e) {
			logger.warn("Cannot find the attribute {} in the current environment because of " + name + " " + e.getMessage());
		}

		return Optional.empty();
	}

	private JSONObject searchXSuaaBinding(final JSONObject jsonObject) throws JSONException {
		for (@SuppressWarnings("unchecked")
		Iterator<String> iter = jsonObject.keys(); iter.hasNext();) {
			JSONObject foundObject = getJSONObjectFromTag(jsonObject.getJSONArray(iter.next()));
			if (foundObject != null) {
				return foundObject;
			}
		}
		return null;
	}

	private JSONObject getJSONObjectFromTag(final JSONArray jsonArray) throws JSONException {
		JSONObject xsuaaBinding = null;
		for (int i = 0; i < jsonArray.length(); i++) {
			JSONObject binding = jsonArray.getJSONObject(i);
			JSONArray tags = binding.getJSONArray(TAGS);

			for (int j = 0; j < tags.length(); j++) {
				if (tags.getString(j).equals(XSUAA_TAG)) {
					if (xsuaaBinding == null) {
						xsuaaBinding = binding;
					} else {
						throw new RuntimeException("Found more than one xsuaa binding. There can only be one.");
					}
				}
			}
		}
		return xsuaaBinding;
	}
}