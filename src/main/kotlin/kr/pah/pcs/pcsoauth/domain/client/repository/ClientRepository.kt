package kr.pah.pcs.pcsoauth.domain.client.repository

import kr.pah.pcs.pcsoauth.domain.client.Client
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface ClientRepository: JpaRepository<Client, UUID> {
}