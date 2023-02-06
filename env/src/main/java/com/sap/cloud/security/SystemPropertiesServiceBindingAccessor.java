/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.exception.ServiceBindingAccessException;

import javax.annotation.Nonnull;
import java.util.List;

public class SystemPropertiesServiceBindingAccessor implements ServiceBindingAccessor {
    private final SapVcapServicesServiceBindingAccessor delegateAccessor;

    public SystemPropertiesServiceBindingAccessor() {
        this.delegateAccessor = new SapVcapServicesServiceBindingAccessor(System::getProperty);
    }

    @Nonnull
    @Override
    public List<ServiceBinding> getServiceBindings() throws ServiceBindingAccessException {
        return delegateAccessor.getServiceBindings();
    }
}
