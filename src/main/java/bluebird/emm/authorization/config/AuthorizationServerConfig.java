package bluebird.emm.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/*
    OAuth 특화 빈을 생성하기 위한 클래스
*/
@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    /*
        클라이언트가 인증 서버에
        권한 부여 코드를 부여받기 위해 전달해야 하는 정보들.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("api-client") // 어떤 클라이언트가 자원에 접근을 시도하고 있는지 알기 위한 정보
                .clientSecret("{noop}api-client-secret") // 클라이언트<->인증 서버간 서로를 신뢰할 수 있는 정보
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC) // (Id, Password 만 요구)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // authorization code를 클라이언트가 생성할 수 있도록 권한 위임
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 리프레시 토큰을 클라이언트가 생성할 수 있도록 권한 위임
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc")// 클라이언트가 사용할 redirect uri를 설정합니다.
                .redirectUri("http://127.0.0.1:8080/authorized") // 클라이언트가 사용할 redirect uri를 설정합니다.
                .scope(OidcScopes.OPENID) // 클라이언트가 사용할 수 있는 권한을 스코프로 설정합니다.
                .scope("articles.read") // custom 권한 스코프 설정
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /*
        기본 OAuth security 및 기본 로그인 페이지 생성 (Oauth2 용)
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /*
   암호화 키를 저장하는 방식.
   rsa256 방식으로 설정했다.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /*
        signing key 를 제외하고,
        각 인증 서버에는 고유한 발급자 URL 이 있어야 하므로
        이 발급자에 대한 URL 을 http://auth-server:9000
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://auth-server:9000")
                .build();
    }
}
