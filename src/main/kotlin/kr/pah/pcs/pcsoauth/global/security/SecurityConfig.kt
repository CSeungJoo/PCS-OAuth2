package kr.pah.pcs.pcsoauth.global.security

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import kr.pah.pcs.pcsoauth.domain.client.repository.ClientRepository
import kr.pah.pcs.pcsoauth.domain.client.repository.CustomRegisteredClientRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*
import java.util.List


@Configuration
@EnableWebSecurity
class SecurityConfig(
    @Value("\${security.seed}")
    private val seed: String,

    private val clientRepository: ClientRepository,
) {

    @Bean
    fun pwdEncoder() : PasswordEncoder {
        return BCryptPasswordEncoder();
    }

    @Bean
    @Throws(Exception::class)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java).oidc(Customizer.withDefaults())
        http.exceptionHandling {
            it.defaultAuthenticationEntryPointFor(
                LoginUrlAuthenticationEntryPoint("/login"),
                MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        }
        http.oauth2ResourceServer {
            it.jwt(Customizer.withDefaults())
        }
        return http.build()
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity) : SecurityFilterChain {
        http
            .csrf {
                it.disable()
            }
            .authorizeHttpRequests {
                it
                    .requestMatchers("/").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin {
                it
                    .usernameParameter("email")
            }

        return http.build()
    }
    @Bean
    fun customRegisteredClientRepository(): CustomRegisteredClientRepository {
        val customRegisteredClientRepository = CustomRegisteredClientRepository()
        for (client in clientRepository.findAll()) {
            customRegisteredClientRepository.save(RegisteredClient.withId(client.id.toString())
                .clientName(client.clientName)
                .clientId(client.clientId)
                .clientSecret(client.secretKey)
                .redirectUri(client.uri)
                .postLogoutRedirectUri("/logout")
                .scopes {
                    it.add(OidcScopes.OPENID)
                    it.add(OidcScopes.PROFILE)
                }
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Basic Authentication
                .authorizationGrantTypes {
                    it.add(AuthorizationGrantType.AUTHORIZATION_CODE)
                    it.add(AuthorizationGrantType.REFRESH_TOKEN)
                }
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(60)).build())
                .build()
            )
        }
        return customRegisteredClientRepository
    }


//    @Bean
//    fun registeredClientRepository(passwordEncoder: PasswordEncoder): RegisteredClientRepository {
//        val client = RegisteredClient.withId(UUID.randomUUID().toString())
//            .clientName("Your client name")
//            .clientId("your-client")
//            .clientSecret("{noop}your-secret")
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Basic Authentication
//            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // client_credentials
//            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(60)).build())
//            .build()
//        return InMemoryRegisteredClientRepository(client)
//    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        val jwtDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource) as NimbusJwtDecoder
        jwtDecoder.setJwtValidator(
            DelegatingOAuth2TokenValidator(
                List.of<OAuth2TokenValidator<Jwt>>(
                    JwtTimestampValidator(Duration.ofSeconds(0)) // 디폴트 세팅으로는 expire 체크시 60초의 유예시간을 두고 체크하고 있는데, 유예시간을 제거하기 위한 설정
                )
            )
        )
        return jwtDecoder
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair: KeyPair = keyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
        return ImmutableJWKSet(JWKSet(rsaKey))
    }

    @Throws(NoSuchAlgorithmException::class)
    fun keyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        val secureRandom: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
        secureRandom.setSeed(seed.toByteArray(StandardCharsets.UTF_8)) // 서버 재실행할 경우 이전에 발급했던 Jwt 토큰을 계속 사용할 수 있도록 고정된 시드값 설정.
        keyPairGenerator.initialize(2048, secureRandom)
        return keyPairGenerator.generateKeyPair()
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
            .build()
    }
}