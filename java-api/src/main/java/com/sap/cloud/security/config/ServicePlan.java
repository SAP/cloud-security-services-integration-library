/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

/**
 * Represents the service plans on SAP BTP.
 */
public enum ServicePlan {
    DEFAULT, BROKER, APPLICATION, SPACE, APIACCESS, SYSTEM;

    public static ServicePlan from(String planAsString) {
        if (planAsString == null) {
            return APPLICATION;
        }
        return ServicePlan.valueOf(planAsString.toUpperCase());
    }

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }
}