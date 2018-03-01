/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.sonova.nephele.shared.security.oauth2.autoconfigure;

import io.sonova.nephele.shared.security.oauth2.provider.token.ResourceServerJwtTokenServices;
import io.sonova.nephele.shared.security.oauth2.provider.token.SonovaUserAuthenticationConverter;
import io.sonova.nephele.shared.security.oauth2.provider.token.store.SonovaMultiCertJwtAccessTokenConverter;
import io.sonova.nephele.shared.security.oauth2.utils.CertificateUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.JwtAccessTokenConverterConfigurer;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration for an OAuth2 resource server.
 * Supports multiple Idp configurations.
 */
@Configuration
@ConditionalOnMissingBean(AuthorizationServerEndpointsConfiguration.class)
public class SonovaResourceServerTokenServicesConfiguration {

	private static final Log logger = LogFactory
			.getLog(SonovaResourceServerTokenServicesConfiguration.class);

	@Configuration
	@ConditionalOnMissingBean(DefaultTokenServices.class)
	protected static class JwtTokenServicesConfiguration {


		@Autowired
		private ResourceServerProperties resource;

		@Autowired(required = false)
		private List<JwtAccessTokenConverterConfigurer> configurers = Collections
				.emptyList();

		@Autowired
		private IdpConfig idpConfig;

		@Bean
		public ResourceServerJwtTokenServices jwtTokenServices() {
			ResourceServerJwtTokenServices services = new ResourceServerJwtTokenServices();

			Map<String, TokenStore> tokenStores = new HashMap<>();
			TokenStore jwtTokenStore = jwtTokenStore();
			idpConfig.getJwt().getCertUris().stream().forEach(certUri -> tokenStores.put(certUri,jwtTokenStore));
			idpConfig.getJwt().getCertBaseUris().stream().forEach(certBaseUri -> tokenStores.put(certBaseUri,jwtTokenStore));
			idpConfig.getJwk().getKeySetUris().stream().forEach(keySetUri -> tokenStores.put(keySetUri, new JwkTokenStore(keySetUri,defaultAccessTokenConverter())));

			services.setResourceServerTokenStores(tokenStores);

			return services;
		}

		@Bean
		public TokenStore jwtTokenStore() {
			return new JwtTokenStore(jwtTokenEnhancer());
		}

		@Bean
		public JwtAccessTokenConverter jwtTokenEnhancer() {
			SonovaMultiCertJwtAccessTokenConverter converter = new SonovaMultiCertJwtAccessTokenConverter();
			converter.setAccessTokenConverter(defaultAccessTokenConverter());

			idpConfig.getJwt().getCertUris().stream().forEach(certUri -> addCertificateToConverter(certUri, converter));
			converter.getCertificateBaseUrls().addAll(idpConfig.getJwt().getCertBaseUris());

			AnnotationAwareOrderComparator.sort(this.configurers);
			for (JwtAccessTokenConverterConfigurer configurer : this.configurers) {
				configurer.configure(converter);
			}
			return converter;
		}

		@Bean
        public DefaultAccessTokenConverter defaultAccessTokenConverter(){
		    DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
		    defaultAccessTokenConverter.setUserTokenConverter(sonovaUserAuthenticationConverter());
		    return defaultAccessTokenConverter;
        }

        @Bean
        public SonovaUserAuthenticationConverter sonovaUserAuthenticationConverter() {
            return new SonovaUserAuthenticationConverter();
        }


		private void addCertificateToConverter(String certUri, SonovaMultiCertJwtAccessTokenConverter converter) {
			String keyValue = "";
			if (StringUtils.hasText(certUri)) {
				try {
					keyValue = CertificateUtil.getKeyFromServer(certUri, this.resource.getClientId(), this.resource.getClientSecret());
				} catch (RestClientException ex) {
					logger.warn("Failed to fetch token key (you may need to refresh "
							+ "when the auth server is back)");
				}
			}

			if (StringUtils.hasText(keyValue) && keyValue.startsWith("-----BEGIN CERTIFICATE")) {
				keyValue = CertificateUtil.getPublicKey(keyValue);
				converter.getCertificateStore().put(certUri, keyValue);
			}
		}


	}
}
