/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package io.sonova.nephele.shared.security.oauth2.provider.token.store;

import io.sonova.nephele.shared.security.oauth2.utils.CertificateUtil;
import io.sonova.nephele.shared.security.oauth2.utils.JwtUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * Extends the default Jwt AccessToken converter to support AccessTokens from multiple IDPs.
 * The certificates / public keys used to validate the signature can either be configured by adding
 * an URL pointing to the certificate in the security.oauth2.resource.jwt.cert-uris property or
 * by adding a base url via the security.oauth2.resource.jwt.cert-base-uris property pointing to an
 * endpoint that accepts the x509 cert thumbprint as parameter and returns the appropriate certificate.
 * This thumbprint can be provided within the JWT header as x5t attribute.
 *
 * @author Dave Gehrig
 * @see JwtAccessTokenConverter
 */
public class SonovaMultiCertJwtAccessTokenConverter extends JwtAccessTokenConverter {


    private static final Log logger = LogFactory.getLog(SonovaMultiCertJwtAccessTokenConverter.class);

    private static final String ISS = "iss";

    private JsonParser objectMapper = JsonParserFactory.create();

    private Map<String, String> certificateStore = new HashMap<>();

    private List<String> certificateBaseUrls = new ArrayList<>();

    protected Map<String, Object> decode(String token) {
        try {
            Jwt jwt = JwtHelper.decode(token);
            String content = jwt.getClaims();
            Map<String, Object> map = objectMapper.parseMap(content);

            if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
                Integer intValue = (Integer) map.get(EXP);
                map.put(EXP, Long.valueOf(intValue));
            }

            final String issuer = (String) map.get(ISS);
            String publicKey = null;

            for (Map.Entry<String, String> entry : certificateStore.entrySet()) {
                if (entry.getKey().startsWith(issuer)) {
                    publicKey = entry.getValue();
                    logger.debug("Matching public key found in local store, for entry: " + entry.getKey());
                }
            }

            if (!StringUtils.hasText(publicKey)) {
                publicKey = getPublicKeyFromRemoteBasedOnX5THeader(token, issuer);
            }

            if (!StringUtils.hasText(publicKey)) {
                logger.warn(String.format("No valid certificate url configured for issuer: %s", issuer));
                throw new InvalidTokenException(String.format("No valid certificate url configured for issuer: %s", issuer));
            }

            final SignatureVerifier verifier = CertificateUtil.createSignatureVerifier(publicKey);
            jwt.verifySignature(verifier);
            return map;
        } catch (Exception e) {
            throw new InvalidTokenException("Cannot convert access token to JSON", e);
        }
    }

    private String getPublicKeyFromRemoteBasedOnX5THeader(String token, String issuer) {
        String remoteKey = "";
        String x5tThumbprint = (String) JwtUtil.getJwtHeaderParams(token).get("x5t");
        if (!StringUtils.isEmpty(x5tThumbprint)) {
            try {
                String currentCertBaseUrl = certificateBaseUrls.stream().filter(baseUrl -> baseUrl.startsWith(issuer)).findFirst().get();
                String certUrl = currentCertBaseUrl + x5tThumbprint;

                if (!StringUtils.isEmpty(currentCertBaseUrl)) {
                    logger.debug("Loading cert from Url: " + certUrl);
                    String remoteX509Cert = CertificateUtil.getKeyFromServer(certUrl);
                    remoteKey = CertificateUtil.getPublicKey(remoteX509Cert);
                    certificateStore.put(certUrl, remoteKey);
                }
            }
            catch (NoSuchElementException e){
                logger.warn(String.format("No certificate download url found for x5t thumbprint: %s and issuer: %s",x5tThumbprint,issuer));
            }
        } else {
            logger.warn("No x5t JWT header param present");
        }
        return remoteKey;
    }

    public Map<String, String> getCertificateStore() {
        return certificateStore;
    }

    public List<String> getCertificateBaseUrls() {
        return certificateBaseUrls;
    }

}
