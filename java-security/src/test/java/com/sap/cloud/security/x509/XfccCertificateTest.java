/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class XfccCertificateTest {

  private static final String valid_xfcc_element =
      "Hash=2b9ce0ea64db2a56705b09522eb049410be0a38e0c0813c27707dd2ac825f3e8;Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIFyDCCA7CgAwIBAgIRANyTEkQpUAuc%2Fnpvrhs9D%2FgwDQYJKoZIhvcNAQELBQAw%0AgYAxCzAJBgNVBAYTAkRFMRQwEgYDVQQHDAtFVTEwLUNhbmFyeTEPMA0GA1UECgwG%0AU0FQIFNFMSMwIQYDVQQLDBpTQVAgQ2xvdWQgUGxhdGZvcm0gQ2xpZW50czElMCMG%0AA1UEAwwcU0FQIENsb3VkIFBsYXRmb3JtIENsaWVudCBDQTAeFw0yNDEyMDYwOTA2%0AMjhaFw0yNTAxMDcxMDA2MjhaMIGtMQswCQYDVQQGEwJERTEPMA0GA1UEChMGU0FQ%0AIFNFMSMwIQYDVQQLExpTQVAgQ2xvdWQgUGxhdGZvcm0gQ2xpZW50czEPMA0GA1UE%0ACxMGQ2FuYXJ5MRkwFwYDVQQLExBzYXAtcHJvdmlzaW9uaW5nMR0wGwYDVQQHExRT%0AdWJzY3JpcHRpb24gTWFuYWdlcjEdMBsGA1UEAxMUU3Vic2NyaXB0aW9uIE1hbmFn%0AZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrr%2BUzzk2UQXLId%2Bd%2B%0Ao9t2glaNQlmED%2BEpUdzbbd6K8TZQeMoXIIp9f5hhNQRa8lwFJ9WJ6OoKfrzeK%2Fkr%0AZMBirNekQznOb0LwN9eDSogbfCV9dDaOpMHJC58UCsRiSkWP8RLTkthftef1QJre%0ASz%2F%2B%2BWaQCyFddrHop6BirbZf5qlHBanDQEItZFozQIgZtl1E7VOZEPBqI6zioVTG%0AbugPZeneMsPK2EJsZWGYnRloRGUDKcQn3wk6Mq81WxrML9rU60dZqPsbEJB7FFGz%0AdOO9XoQ5HMl2X1%2FEUr4q3bR40KaNnI%2F2imp2aBFcLL4SNTliMYOgtRTdK3q8X4QS%0Ae6uXAgMBAAGjggEMMIIBCDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFEe81yukGl7o%0AXwWG0y9Db4qUTujNMB0GA1UdDgQWBBQwBp8RYZf36cZhbvX0uIWhyHOcQjAOBgNV%0AHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwgZUGA1UdHwSBjTCBijCB%0Ah6CBhKCBgYZ%2FaHR0cDovL3NhcC1jbG91ZC1wbGF0Zm9ybS1jbGllbnQtY2EtZXUx%0AMC1jYW5hcnktY3Jscy5zMy5ldS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbS9jcmwv%0AZDNjYWM2NzItOTNmMi00MWYwLWEyNTYtNTFkMGM4MTJmZWIyLmNybDANBgkqhkiG%0A9w0BAQsFAAOCAgEACi0wjAq0YePesFnzT1%2BuWIpTYzN28ajPLWkdMLz6ubk%2B%2FYIK%0A43glPdr0%2FP%2BXWJixLvjNu7KtGiMlrrEt3v4hB7v4BvWQGMVKsmbN9GXiDfpsnTay%0ANaEVeTdSZqBKu0lYakSGKkutrGu4tKJKx8JFh9UNgdAsw26nFgtL7O34Z5D8ZNVW%0An4%2Bba8La3Fef1Vk5%2BU%2BIONf9Vc7VFTiFnyHPEGIUG%2FhWqO6L7RQBOzmNWlOj%2BbqJ%0A3tx65NrdQWlMdoDQgmMSPWqjcnnh7bHBP5NnM46ipGFEscD6arztcVUww3h0WVLl%0A2toeh13H8YDeyp5LRT82HxNEPyExcFtDTYupkIh99vlCWUwcdy9oWh7ppWakbSSa%0A51EOwXjJpTeh1Rf6q3eQ9nTi2w4LfHDJHl5yEpZfasVKFWKub1%2Bo7tKvqgkZFH5q%0A1qI9tJBu57d6W0J%2FWTs26z%2FhKUvYph5q9tYt5AoCruKMEdfH0cOUb6DJjHpjVblW%0Ag%2B4JAMBGnJyp4n5LSxJ5rV1SHf9t%2B1iHy933Ml2AhuQYDEZQ%2BxnmyF%2BmsFtE4EV0%0AaJwuYv7oNKsHADBS5aiYXFFA%2F5yKLo3W4RytVDLho4U8l7gJL8AzZ%2F9CEZGGJnDj%0Amba%2Fw1KfuFnLyhXKCwP009pcQiDQP7PK7yPRpSsjbiPeSFo%2FCWOB90nH3mA%3D%0A-----END%20CERTIFICATE-----%0A\";Subject=\"CN=Subscription"
          + " Manager,L=Subscription Manager,OU=sap-provisioning,OU=Canary,OU=SAP Cloud Platform"
          + " Clients,O=SAP"
          + " SE,C=DE\";URI=,By=spiffe://cluster.local/ns/ams/sa/bookshop-srv;Hash=43257daed447d527b759dacd11c72de607f634e1286b64be789ecc4fa4f5cad1;Subject=\"\";URI=spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account";

  @Test
  void headerWithSingleValidElement() {
    X509Certificate cert = X509Certificate.newCertificate(valid_xfcc_element);
    assertThat(cert).isNotNull();
  }

  @Test
  void headerWithTwoValidElements() {
    X509Certificate cert =
        X509Certificate.newCertificate(valid_xfcc_element + ',' + valid_xfcc_element);
    assertThat(cert).isNotNull();
  }

  @Test
  void headerWithValidElementLast() {
    X509Certificate cert =
        X509Certificate.newCertificate("Hash=invalid;Cert=invalid," + valid_xfcc_element);
    assertThat(cert).isNotNull();
  }

  @Test
  void headerWithValidElementFirst() {
    X509Certificate cert =
        X509Certificate.newCertificate(valid_xfcc_element + ",Hash=invalid;Cert=invalid");
    assertThat(cert).isNull();
  }
}
