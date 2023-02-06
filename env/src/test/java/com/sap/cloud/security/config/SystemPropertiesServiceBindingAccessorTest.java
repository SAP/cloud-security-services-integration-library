/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.security.SystemPropertiesServiceBindingAccessor;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ServiceLoader;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class SystemPropertiesServiceBindingAccessorTest {

    @Test
    void getsLoadedByServiceLoader() {
        ServiceLoader<ServiceBindingAccessor> serviceLoader = ServiceLoader.load(ServiceBindingAccessor.class);

        Stream<String> loadedClassNames =
                StreamSupport.stream(serviceLoader.spliterator(), false)
                .map(Object::getClass)
                .map(Class::getName);
        Assertions.assertThat(loadedClassNames).contains(SystemPropertiesServiceBindingAccessor.class.getName());
    }
}
