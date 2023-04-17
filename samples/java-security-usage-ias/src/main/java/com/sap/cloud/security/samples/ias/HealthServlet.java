/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples.ias;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet(HealthServlet.HEALTH)
public class HealthServlet extends HttpServlet {

	static final String HEALTH = "/health";

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		resp.getWriter().write("OK");
	}
}
