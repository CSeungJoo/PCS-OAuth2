package kr.pah.pcs.pcsoauth.domain.client.repository

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.util.concurrent.ConcurrentHashMap

class CustomRegisteredClientRepository: RegisteredClientRepository {
    private val registeredClients: MutableMap<String, RegisteredClient> = ConcurrentHashMap()
    override fun findById(id: String?): RegisteredClient? {
        return registeredClients[id]
    }

    override fun findByClientId(clientId: String?): RegisteredClient? {
        return registeredClients.values.find { it.clientId == clientId }
    }

    override fun save(registeredClient: RegisteredClient?) {
        registeredClients[registeredClient!!.clientId] = registeredClient
    }
}
