package io.sonova.nephele.shared.security.oauth2.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix="security.oauth2.resource")
public class IdpConfig {


    private Jwt jwt = new Jwt();
    private Jwk jwk = new Jwk();

    public class Jwt {

        private List<String> certUris;
        private List<String> certBaseUris;

        public List<String> getCertUris() {
            if (certUris == null) {
                certUris = new ArrayList<>();
            }
            return certUris;
        }

        public List<String> getCertBaseUris() {
            if (certBaseUris == null) {
                certBaseUris = new ArrayList<>();
            }
            return certBaseUris;
        }

    }

    public class Jwk {
        private List<String> keySetUris;

        public List<String> getKeySetUris() {
            if (keySetUris == null) {
                keySetUris = new ArrayList<>();
            }
            return keySetUris;
        }

    }


    public Jwt getJwt() {
        return jwt;
    }

    public Jwk getJwk() {
        return jwk;
    }

}



