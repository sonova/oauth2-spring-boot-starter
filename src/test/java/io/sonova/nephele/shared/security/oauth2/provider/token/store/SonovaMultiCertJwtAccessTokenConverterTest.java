package io.sonova.nephele.shared.security.oauth2.provider.token.store;

import io.sonova.nephele.shared.security.oauth2.provider.token.SonovaUserAuthenticationConverter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;

import java.io.InputStream;
import java.util.*;

/**
 * External system dependencies configured via test.properties
 */
public class SonovaMultiCertJwtAccessTokenConverterTest {

    private SonovaMultiCertJwtAccessTokenConverter tokenEnhancer;

    private Authentication userAuthentication;
    private Properties props;


    @Before
    public void setUp() throws Exception {

        props = new Properties();
        InputStream is = ClassLoader.getSystemResourceAsStream("test.properties");
        props.load(is);

        tokenEnhancer = new SonovaMultiCertJwtAccessTokenConverter();

        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        UserAuthenticationConverter sonovaUserAuthenticationConverter = new SonovaUserAuthenticationConverter();
        defaultAccessTokenConverter.setUserTokenConverter(sonovaUserAuthenticationConverter);
        tokenEnhancer.setAccessTokenConverter(defaultAccessTokenConverter);

        userAuthentication = new TestAuthentication("test", true);
    }

    @Test
    public void testProvidedPublicKey() throws Exception {
        String rsaKey = "-----BEGIN RSA PRIVATE KEY-----  \n"
                + "MIIBywIBAAJhAOTeb4AZ+NwOtPh+ynIgGqa6UWNVe6JyJi+loPmPZdpHtzoqubnC \n"
                + "wEs6JSiSZ3rButEAw8ymgLV6iBY02hdjsl3h5Z0NWaxx8dzMZfXe4EpfB04ISoqq\n"
                + "hZCxchvuSDP4eQIDAQABAmEAqUuYsuuDWFRQrZgsbGsvC7G6zn3HLIy/jnM4NiJK\n"
                + "t0JhWNeN9skGsR7bqb1Sak2uWqW8ZqnqgAC32gxFRYHTavJEk6LTaHWovwDEhPqc\n"
                + "Zs+vXd6tZojJQ35chR/slUEBAjEA/sAd1oFLWb6PHkaz7r2NllwUBTvXL4VcMWTS\n"
                + "pN+5cU41i9fsZcHw6yZEl+ZCicDxAjEA5f3R+Bj42htNI7eylebew1+sUnFv1xT8\n"
                + "jlzxSzwVkoZo+vef7OD6OcFLeInAHzAJAjEAs6izolK+3ETa1CRSwz0lPHQlnmdM\n"
                + "Y/QuR5tuPt6U/saEVuJpkn4LNRtg5qt6I4JRAjAgFRYTG7irBB/wmZFp47izXEc3\n"
                + "gOdvA1hvq3tlWU5REDrYt24xpviA0fvrJpwMPbECMAKDKdiDi6Q4/iBkkzNMefA8\n"
                + "7HX27b9LR33don/1u/yvzMUo+lrRdKAFJ+9GPE9XFA== \n"
                + "-----END RSA PRIVATE KEY----- ";

        String publicKey = "-----BEGIN RSA PUBLIC KEY-----\n"
                + "MGgCYQDk3m+AGfjcDrT4fspyIBqmulFjVXuiciYvpaD5j2XaR7c6Krm5wsBLOiUo\n"
                + "kmd6wbrRAMPMpoC1eogWNNoXY7Jd4eWdDVmscfHczGX13uBKXwdOCEqKqoWQsXIb\n"
                + "7kgz+HkCAwEAAQ==\n"
                + "-----END RSA PUBLIC KEY-----";

        tokenEnhancer.setSigningKey(rsaKey);

        tokenEnhancer.getCertificateStore().put("https://int-signon.test.com",publicKey);

        OAuth2Authentication authentication = new OAuth2Authentication(
                createOAuth2Request("foo", null), userAuthentication);
        DefaultOAuth2AccessToken accessToken= new DefaultOAuth2AccessToken(
                "FOO");
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("iss","https://int-signon.test.com");
        accessToken.setAdditionalInformation(additionalInformation);

        OAuth2AccessToken token = tokenEnhancer.enhance(accessToken, authentication);
        Map<String,Object> tokenPayload = tokenEnhancer.decode(token.getValue());
        Assert.assertNotNull(tokenPayload);
        Assert.assertEquals((String)tokenPayload.get("iss"),"https://int-signon.test.com");
    }

    @Test
    public void testX5tCertLookup(){
        String accessToken = props.getProperty("jwtIdpAccessToken");
        tokenEnhancer.getCertificateBaseUrls().add(props.getProperty("jwtIdpX5tUrl"));
        Map<String,Object> tokenPayload = tokenEnhancer.decode(accessToken);
        Assert.assertNotNull(tokenPayload);
        Assert.assertEquals((String)tokenPayload.get("iss"),props.getProperty("jwtIdpIssuer"));
    }

    private OAuth2Request createOAuth2Request(String clientId, Set<String> scope) {
        return new OAuth2Request(Collections.<String, String> emptyMap(), clientId, null,
                true, scope, null, null, null, null);
    }

    protected static class TestAuthentication extends AbstractAuthenticationToken {

        private static final long serialVersionUID = 1L;

        private String principal;

        public TestAuthentication(String name, boolean authenticated) {
            super(null);
            setAuthenticated(authenticated);
            this.principal = name;
        }

        public Object getCredentials() {
            return null;
        }

        public Object getPrincipal() {
            return this.principal;
        }
    }

}
