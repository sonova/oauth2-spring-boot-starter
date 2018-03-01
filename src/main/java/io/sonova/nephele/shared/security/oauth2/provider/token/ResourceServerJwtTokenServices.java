package io.sonova.nephele.shared.security.oauth2.provider.token;

import io.sonova.nephele.shared.security.oauth2.utils.JwtUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * TokenServices implementation for resource servers. It allows a resource server to support
 * multiple token stores to validate Access Tokens form multiple IDPs.
 */
public class ResourceServerJwtTokenServices implements ResourceServerTokenServices {

    private static final Log logger = LogFactory.getLog(ResourceServerJwtTokenServices.class);

    private static final String ISS = "iss";

    private JsonParser objectMapper = JsonParserFactory.create();

    private ClientDetailsService clientDetailsService;
    private Map<String, TokenStore> resourceServerTokenStores;

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(resourceServerTokenStores, "tokenStores must be set");
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException, InvalidTokenException {

        TokenStore tokenStore = getTokenStore(accessTokenValue);

        OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException(String.format("Invalid access token: %s", accessTokenValue));
        } else if (accessToken.isExpired()) {
            tokenStore.removeAccessToken(accessToken);
            throw new InvalidTokenException(String.format("Access token expired: %s", accessTokenValue));
        }

        OAuth2Authentication result = tokenStore.readAuthentication(accessToken);
        if (result == null) {
            // in case of race condition
            throw new InvalidTokenException(String.format("Invalid access token: %s", accessTokenValue));
        }
        if (clientDetailsService != null) {
            String clientId = result.getOAuth2Request().getClientId();
            try {
                clientDetailsService.loadClientByClientId(clientId);
            } catch (ClientRegistrationException e) {
                throw new InvalidTokenException(String.format("Client not valid: %s", clientId), e);
            }
        }
        return result;
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        return getTokenStore(accessToken).readAccessToken(accessToken);
    }

    private TokenStore getTokenStore(String accessToken) {
        final TokenStore tokenStore;
        final String issuer;
        try {
            Jwt jwt = JwtHelper.decode(accessToken);
            String content = jwt.getClaims();
            Map<String, Object> map = objectMapper.parseMap(content);
            issuer = (String) map.get(ISS);
            return resourceServerTokenStores.entrySet().stream().filter(tokenStores -> tokenStores.getKey().startsWith(issuer)).map(tokenStores -> tokenStores.getValue()).findFirst().orElseThrow(() -> new InvalidTokenException(String.format("No TokenStore configuration available for issuer %s", issuer)));
        } catch (IllegalArgumentException ex) {
            throw new InvalidTokenException(String.format("Invalid access token: %s", accessToken));
        }
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public Map<String, TokenStore> getResourceServerTokenStores() {
        return resourceServerTokenStores;
    }

    public void setResourceServerTokenStores(Map<String, TokenStore> resourceServerTokenStores) {
        this.resourceServerTokenStores = resourceServerTokenStores;
    }

}
