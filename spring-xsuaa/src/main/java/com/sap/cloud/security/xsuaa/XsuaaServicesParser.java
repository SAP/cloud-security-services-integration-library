package com.sap.cloud.security.xsuaa;


import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

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
	 * @throws ParseException  in case of configuration errors
	 */
	public Optional<String> getAttribute(String name) throws ParseException {

		if (StringUtils.isEmpty(vcapServices)) {
			return Optional.empty();
		}

			JSONObject vcap = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(vcapServices);
			JSONObject xsuaaBinding = searchXSuaaBinding(vcap);

			if (Objects.nonNull(xsuaaBinding) && xsuaaBinding.containsKey(CREDENTIALS)) {
				JSONObject credentials = (JSONObject) xsuaaBinding.get(CREDENTIALS);
				return Optional.ofNullable(credentials.getAsString(name));
			}

		return Optional.empty();
	}

	private JSONObject searchXSuaaBinding(final JSONObject jsonObject)  {
		for (@SuppressWarnings("unchecked")
		String tag : jsonObject.keySet()) {
			JSONObject foundObject = getJSONObjectFromTag((JSONArray)jsonObject.get(tag));
			if (foundObject != null) {
				return foundObject;
			}
		}
		return null;
	}

	private JSONObject getJSONObjectFromTag(final JSONArray jsonArray)  {
		JSONObject xsuaaBinding = null;
		for (int i = 0; i < jsonArray.size(); i++) {
			JSONObject binding = (JSONObject) jsonArray.get(i);
			JSONArray tags = (JSONArray) binding.get(TAGS);

			for (int j = 0; j < tags.size(); j++) {
				if (tags.get(j).equals(XSUAA_TAG)) {
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