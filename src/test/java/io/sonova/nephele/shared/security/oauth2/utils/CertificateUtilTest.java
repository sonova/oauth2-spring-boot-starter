package io.sonova.nephele.shared.security.oauth2.utils;

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateUtilTest {

    private final String certificate="-----BEGIN CERTIFICATE-----\n" +
            "MIIC+jCCAeKgAwIBAgIGAVZ9lM/zMA0GCSqGSIb3DQEBCwUAMD4xCzAJBgNVBAYTAkNIMQ8wDQYD\n" +
            "VQQKEwZQaG9uYWsxHjAcBgNVBAMTFWludC1zaWdub24ucGhvbmFrLmNvbTAeFw0xNjA4MTIwNzA4\n" +
            "MzlaFw0yMjAyMDIwODA4MzlaMD4xCzAJBgNVBAYTAkNIMQ8wDQYDVQQKEwZQaG9uYWsxHjAcBgNV\n" +
            "BAMTFWludC1zaWdub24ucGhvbmFrLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AIYn1fbBwotPyyZ1EQz0TCbUi+ShkmlEUs38eLJduUdEeuzAZAe2hwSl2rOFBkbefiP40OX15rNf\n" +
            "no4pZpmRi8H8pgl5d3qUJ1MBodVT0LnCgyph3ZcSKEUhdtPNsO0UcXsfMfpCsQDkRjvieyBOYs3P\n" +
            "2cECXUz0z2s9Iaso3RS/zmmeKu4j1Fm4h3GamNm+A1Dl7aAKDzxtwE9C8mmlgS1jKOR78XTthJGP\n" +
            "QSIqNB3AQ4241Nr0mM9o3ZROLLDWRKG/QxkFuLwfiLNquQcfVpgDTI/Q+dlM2XmnVLmrbJam+U5S\n" +
            "aun4MErmjzOMu2bCIwhoLOkAd2BRevZQlmpGHPcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAMgQ3\n" +
            "bdnaF+iCzrf5nfjxSow1unsQb/ClDBLHvpZrHMKXJdXHctd0Nd1F+AfX0ObhH0hDPuY+rY6W9lnc\n" +
            "jzFbrWs1Zutm4Y2BSTNOiLHvu/5AI6n01ZUfh1M3FvjLyGz7HuGLqSRq+Vc5HUFOn/dT3RDO2Mav\n" +
            "CD6wkDKeCO+p1Tyxiy+bcQQk8eRHDrLnfkWoBfz1SB7SEXtawduU/pLAd3dXahlzO/dTvPODSzR6\n" +
            "Q2A6NUxXWLRz7ycXNwLwFwdnrftiCRehPhvDyG6mAUvMlME/E/qbuuN3ONUEIgckjrZRttNkHxAs\n" +
            "qLh5bYFstU9AR7AkCRQERqZm2Jfn0sKmtQ==\n" +
            "-----END CERTIFICATE-----";
    private final String extractedPublicKey="-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhifV9sHCi0/LJnURDPRMJtSL5KGSaURSzfx4sl25R0R67MBkB7aHBKXas4UGRt5+I/jQ5fXms1+ejilmmZGLwfymCXl3epQnUwGh1VPQucKDKmHdlxIoRSF2082w7RRxex8x+kKxAORGO+J7IE5izc/ZwQJdTPTPaz0hqyjdFL/OaZ4q7iPUWbiHcZqY2b4DUOXtoAoPPG3AT0LyaaWBLWMo5HvxdO2EkY9BIio0HcBDjbjU2vSYz2jdlE4ssNZEob9DGQW4vB+Is2q5Bx9WmANMj9D52UzZeadUuatslqb5TlJq6fgwSuaPM4y7ZsIjCGgs6QB3YFF69lCWakYc9wIDAQAB-----END PUBLIC KEY-----";


    @Test
    public void getPublicKey() throws Exception {
        Assert.assertNull(CertificateUtil.getPublicKey(null));
        assertEquals("asdf",CertificateUtil.getPublicKey("asdf"));
        assertEquals(extractedPublicKey,CertificateUtil.getPublicKey(certificate));
    }

}