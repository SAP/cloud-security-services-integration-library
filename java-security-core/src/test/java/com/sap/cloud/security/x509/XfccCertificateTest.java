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
          "Subject=\"C=DE, O=SAP SE, OU=SAP Cloud Platform Clients, OU=Staging, OU=cb6f3989-4828-4ac1-89dc-a55929c97763, L=sap-uaa, CN=a43c6936-a6c0-4237-8f1c-e8778d02c86b\";URI="
                  + ";Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIFvDCCA6SgAwIBAgIUf%2FUkQqmFAj56U4mYKYwIBNa1zjcwDQYJKoZIhvcNAQEL%0ABQAwgYIxCzAJBgNVBAYTAkRFMRgwFgYDVQQHDA9jZi11czEwLXN0YWdpbmcxDzAN%0ABgNVBAoMBlNBUCBTRTEYMBYGA1UECwwPU0FQIEJUUCBDbGllbnRzMS4wLAYDVQQD%0ADCVTQVAgUEtJIENlcnRpZmljYXRlIFNlcnZpY2UgQ2xpZW50IENBMB4XDTI0MDQy%0AMTA4MjkxOFoXDTI0MDUyMTA5MjkxOFowgcUxCzAJBgNVBAYTAkRFMQ8wDQYDVQQK%0AEwZTQVAgU0UxIzAhBgNVBAsTGlNBUCBDbG91ZCBQbGF0Zm9ybSBDbGllbnRzMRAw%0ADgYDVQQLEwdTdGFnaW5nMS0wKwYDVQQLEyRjYjZmMzk4OS00ODI4LTRhYzEtODlk%0AYy1hNTU5MjljOTc3NjMxEDAOBgNVBAcTB3NhcC11YWExLTArBgNVBAMTJGE0M2M2%0AOTM2LWE2YzAtNDIzNy04ZjFjLWU4Nzc4ZDAyYzg2YjCCASIwDQYJKoZIhvcNAQEB%0ABQADggEPADCCAQoCggEBAMx3ojKsdkLoOCfa%2FxHy2nbdvn77xlLPs1uw%2FlZFDFXD%0AGwWg1doPXfquRshbHIOCaOVSa3NeI3euH40XXEg7crnjC3t%2BVjwwejrF96TOw%2F%2Bj%0AICJpZN%2BXG44FTAcK%2F2hmgj69r%2BFkxbAL7JjMM42dntjsMI7sz56L9KW6Q%2BYmwRrD%0A7i0nQs57wLVwAevghCUxTzJC3Q8%2BCw4ZryFUZ6pd16TUg5qVCoYFov%2F9S1xMEVXv%0AQBDX36nSS7AvVzVBELsrDu2vpU5rz%2FhibkoUKU3I%2FWUlzwEjvUxR%2BwjgQwwureTy%0AzJXyRsl%2FY%2FoqR5YpuAniH1cfQJg1sU%2ByZVb6O3HnzBcCAwEAAaOB5DCB4TAJBgNV%0AHRMEAjAAMA4GA1UdDwEB%2FwQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNV%0AHQ4EFgQUZy%2FdL96Ejer9oXY9FDCIqon2YdEwHwYDVR0jBBgwFoAU37Av8AHW8rP7%0AbDyxVwGxn9aiTcowbwYDVR0fBGgwZjBkoGKgYIZeaHR0cHM6Ly9jZXJ0aWZpY2F0%0AZS1zZXJ2aWNlLWNybHMuY2Yuc3RhZ2luZ2F3cy5oYW5hdmxhYi5vbmRlbWFuZC5j%0Ab20vMTcxMzY4MzE5Nl8xNzE5MTI5OTk2LmNybDANBgkqhkiG9w0BAQsFAAOCAgEA%0AG3XC7xV3LOZa%2BKRpAH98g7Ji7dSKEm74z0rSNPQAwdmEtNQgE3%2FOlXE1KkEPu%2BaE%0Am61vOl1ZTR6XfQs6%2Fz80F3YYOTE%2F3qP%2FLr579%2ByQJ41QZS5S6f%2BTXhYt3T5r%2FLHF%0Ak7Y1z1NPvQ6ws30%2FuwagwE%2BZIU%2Fz8Pyt0AbumenlcCQs0pfLaZ3VEepckN8iPLGN%0A7YXFY92IBwjo9GmspFhR0yVckVZzHNdzW6gyuXi1m2TNRi9h0fF6Tm8Nq8BdDOOq%0Aef10fipOh7G0GbjWFAiclSbqnaL%2B%2F06j4Pzcl%2Bj8ku7BU%2BUdKQIxyJOmVZqAln7f%0Au%2B3HUyhDWOP9q6F0xZMeMmBOqibbkjYpuexfSIFDM3rimv56kVg38R8H3MhFofAV%0Auv1VI9o3bYbxnWMX5n%2FIgLsqjzCE76mfsC6jmH2b3I57bSgAeSfajzc%2BEEbGormq%0AeKmF8gFJMVn%2FU%2BFG4LOKtY6psvB42VW2sa2SL3DVVitQ%2FaTr8Ilv6eAUD0d1iGJD%0AeWkam8wytOG5qrdIg2qbJ9%2FHI%2BP0n4moHX1zzfrYuQ0WWGH5ZMmmzy0HhQpaRWvf%0Aqx5lRyLiL8pQk64G2Baix3RELNu5XLsJL1iFVCyXf3pxjMWz4nSouTtSQQnYJ9jO%0AIkp0FD78lSFh8iNDlTVkfoALgqXlrvHfhJcRyyebTbs%3D%0A-----END%20CERTIFICATE-----\"";

  private static final String xfcc_element_without_cert =
          "Subject=\"C=DE, O=SAP SE, OU=SAP Cloud Platform Clients, OU=Staging, OU=cb6f3989-4828-4ac1-89dc-a55929c97763, L=sap-uaa, CN=a43c6936-a6c0-4237-8f1c-e8778d02c86b\";URI=";

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
            X509Certificate.newCertificate(valid_xfcc_element + ",Hash=invalid;Cert=");
    assertThat(cert).isNull();
  }

  @Test
  void headerWithoutCertValue() {
    X509Certificate cert =
            X509Certificate.newCertificate(xfcc_element_without_cert);
    assertThat(cert).isNull();
  }
}
