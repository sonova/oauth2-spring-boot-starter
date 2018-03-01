package io.sonova.nephele.shared.security.oauth2.provider.token;

import io.sonova.nephele.shared.security.oauth2.provider.token.store.SonovaMultiCertJwtAccessTokenConverter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;

import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Test cases running against working IDPs to get certificates and tokens.
 * Configured via test.properties.
 */
public class ResourceServerJwtTokenServicesTest {

    private ResourceServerJwtTokenServices services;
    private Properties props;

    @Before
    public void setUp() throws Exception {

        props = new Properties();
        InputStream is = ClassLoader.getSystemResourceAsStream("test.properties");
        props.load(is);

        services = new ResourceServerJwtTokenServices();
        SonovaMultiCertJwtAccessTokenConverter converter = new SonovaMultiCertJwtAccessTokenConverter();
        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new SonovaUserAuthenticationConverter());
        converter.setAccessTokenConverter(defaultAccessTokenConverter);

        Map<String, TokenStore> tokenStores = new HashMap<>();
        String jwkSetUrl = props.getProperty("jwkSetUrl");
        String jwtUrl = props.getProperty("jwtIdpX5tUrl");

        converter.getCertificateBaseUrls().add(jwtUrl);

        TokenStore jwtTokenStore = new JwtTokenStore(converter);
        TokenStore jwkTokenStore = new JwkTokenStore(jwkSetUrl,defaultAccessTokenConverter);

        tokenStores.put(jwtUrl,jwtTokenStore);
        tokenStores.put(jwkSetUrl, jwkTokenStore);
        services.setResourceServerTokenStores(tokenStores);
    }

    @Test
    public void testAccessTokenValidationWithDifferentTokenStores() throws Exception {

        OAuth2AccessToken phonakAccessToken = services.readAccessToken(props.getProperty("jwtIdpAccessToken"));
        Assert.assertEquals(props.getProperty("jwtIdpIssuer"), phonakAccessToken.getAdditionalInformation().get("iss"));

        OAuth2AccessToken sonovaAccessToken = services.readAccessToken(props.getProperty("jwkIdpAccessToken"));
        Assert.assertEquals(props.getProperty("jwkIdpIssuer"), sonovaAccessToken.getAdditionalInformation().get("iss"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testUnknownIssuerAccessTokenValidation() throws Exception {
        OAuth2AccessToken phonakAccessToken = services.readAccessToken(props.getProperty("jwtIdp2AccessToken"));
    }

    @Test
    @Ignore
    public void testAuthenticationLoadWithClientCredentials() throws Exception {
        ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
        resourceDetails.setId("1");

        resourceDetails.setClientId(props.getProperty("jwkIntTestClientId"));
        resourceDetails.setClientSecret(props.getProperty("jwkIntTestClientSecret"));
        resourceDetails.setAccessTokenUri(props.getProperty("jwkIntTestAccessTokenUri"));
        resourceDetails.setScope(Collections.singletonList(props.getProperty("jwkIntTestScope")));


        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails, new DefaultOAuth2ClientContext());
        final OAuth2AccessToken accessToken = restTemplate.getAccessToken();

        OAuth2Authentication oAuth2Authentication = services.loadAuthentication(accessToken.getValue());
        Assert.assertEquals(props.getProperty("jwkIntTestClientId"), oAuth2Authentication.getPrincipal());
    }


}