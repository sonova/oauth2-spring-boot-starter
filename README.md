# Oauth2 security library for Spring boot resource server projects

Extends the default Jwt AccessToken converter to support AccessTokens issued by multiple IDPs with different certificates.
In parallel, validation via JWKS is supported, too.   

### Direct certificate mapping
The certificates / public keys used to validate the signature can either be configured by adding an URL pointing to the certificate in the 

    security.oauth2.resource.jwt.cert-uris 

property list or by adding a base url via the 

    security.oauth2.resource.jwt.cert-base-uris 
    
property list pointing to an endpoint that accepts the x509 cert thumbprint as parameter and returns the appropriate certificate. 
This thumbprint must be provided within the JWT header of the validated Access Token as x5t attribute. The library takes the x5t thumbprint
 and downloads the certificate from the configured URL, with the thumbprint as parameter. 

### JSON Web Key Sets
With version 1.2, support for AccessToken validation via an JWKSet was added.
Resource servers can configure a JWKSet via the 

    security.oauth2.resource.jwk.key-set-uris 

property array.

### Sample config in a SpringBoot resource server project
```yaml
security:
 oauth2:
   resource:
    id: https://appid.company.io/api/dev
    jwt:
       cert-base-uris:
         - https://sso.idp1.com/ext/oauth/x509/x5t?v=
         - https://sso.idp2.com/ext/oauth/x509/x5t?v=
    jwk:
       key-set-uris:
         - https://sso.idp3.io/.well-known/openid-configuration/jwks
```
## Security Principal mapping
Instead of using the user_name claim within the AccessToken, this library uses the sub claim to map a token to a Spring Security Principal.

## Spring boot project configuration
To use this library, some tweaks are needed on the application consuming this library.
### Disable Auto-configuration
When using this library, make sure to disable the Spring boot default oauth2 auto configuration by setting the 

    spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.security.oauth2.OAuth2AutoConfiguration 
   
property in the application.properties file.
### Change version of Spring Security Oauth library
Within your maven project pom.xml file, define the following property to use the appropriate Oauth library needed by this library to work:
 
    <spring-security-oauth.version>2.0.14.RELEASE</spring-security-oauth.version>


