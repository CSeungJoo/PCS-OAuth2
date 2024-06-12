package kr.pah.pcs.pcsoauth.domain.client.controller

import jakarta.transaction.Transactional
import kr.pah.pcs.pcsoauth.domain.client.Client
import kr.pah.pcs.pcsoauth.domain.client.repository.ClientRepository
import kr.pah.pcs.pcsoauth.domain.client.repository.CustomRegisteredClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Duration

@RestController
class ClientController(
    private val clientRepository: ClientRepository,
    private val customRegisteredClientRepository: CustomRegisteredClientRepository,
) {

    @GetMapping("/test")
    @Transactional
    fun testInit() {
        val client = clientRepository.save(Client(null, "a", "a", "a", "/", true, null))
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
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(60)).build())
            .build())
    }
}