package io.sonova.nephele.shared.security.oauth2.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Util class handling certificate specific tasks.
 */
public class CertificateUtil {

    private static final Log logger = LogFactory.getLog(CertificateUtil.class);

    /**
     * Extracts the public key out of the given x509 certificate. If extraction fails, the same value as inserted will be returned.
     * @param x509Certificate
     * @return Public key including header and footer string.
     */
    public static String getPublicKey(String x509Certificate){
        if (!StringUtils.isEmpty(x509Certificate)) {

            CertificateFactory f = null;
            try {
                f = CertificateFactory.getInstance("X.509");
                InputStream certStream = new ByteArrayInputStream(x509Certificate.getBytes(StandardCharsets.UTF_8));
                X509Certificate certificate = (X509Certificate) f.generateCertificate(certStream);
                PublicKey pk = certificate.getPublicKey();
                String base64encodedPk = wrapWithPemPubKeyLabel(new String(Base64.encode(pk.getEncoded()),StandardCharsets.UTF_8));
                return base64encodedPk;
            } catch (CertificateException e) {
                logger.warn("Couldn't extract public key from cert");
            }
        }
        return x509Certificate;
    }

    private static String wrapWithPemPubKeyLabel(String key) {
        return "-----BEGIN PUBLIC KEY-----" + key + "-----END PUBLIC KEY-----";

    }

    public static String getKeyFromServer(String certUri){
        return getKeyFromServer(certUri, "", "");
    }

    public static String getKeyFromServer(String certUri, String clientId, String clientSecret){

            HttpHeaders headers = new HttpHeaders();
            String username = clientId;
            String password = clientSecret;
            if (username != null && password != null) {
                byte[] token = Base64.encode((username + ":" + password).getBytes(StandardCharsets.UTF_8));
                headers.add("Authorization", "Basic " + new String(token, StandardCharsets.UTF_8));
            }
            HttpEntity<Void> request = new HttpEntity<Void>(headers);
            String url = certUri;
            RestTemplate keyUriRestTemplate = new RestTemplate();

            return (String) keyUriRestTemplate
                    .exchange(url, HttpMethod.GET, request, String.class).getBody();

    }

    public static SignatureVerifier createSignatureVerifier(final String verifierKey)
    {
        SignatureVerifier verifier = new MacSigner(verifierKey);
        try
        {
            verifier = new RsaVerifier(verifierKey);
        }
        catch (final Exception e)
        {
            logger.warn("Unable to create an RSA verifier from verifierKey (ignoreable if using MAC)");
        }
        return verifier;
    }

}
