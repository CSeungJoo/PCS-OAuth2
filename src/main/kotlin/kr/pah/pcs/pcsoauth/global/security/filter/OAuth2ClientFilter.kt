package kr.pah.pcs.pcsoauth.global.security.filter

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletResponse
import kr.pah.pcs.pcsoauth.domain.client.repository.ClientRepository
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.stereotype.Component
import java.util.*

@Component
class OAuth2ClientFilter(
    private val clientRepository: ClientRepository
): Filter {
    override fun doFilter(request: ServletRequest?, response: ServletResponse?, chain: FilterChain?) {
        val clientId: String = request!!.getParameter(OAuth2ParameterNames.CLIENT_ID)

        var client = clientRepository.findById(UUID.fromString(clientId))

        if (client.isEmpty || !client.get().isAllowed) {
            val res: HttpServletResponse = response as HttpServletResponse
            val error = OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Invalid client ID",
                "/auth/error"
            )

            res.status = HttpServletResponse.SC_UNAUTHORIZED
            return
        }

        chain?.doFilter(request, response)
    }

}