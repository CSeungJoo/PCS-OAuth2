package kr.pah.pcs.pcsoauth.domain.client

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.ManyToOne
import jakarta.persistence.OneToMany
import jakarta.persistence.PrePersist
import kr.pah.pcs.pcsoauth.domain.User.User
import java.time.LocalTime
import java.util.UUID

@Entity
class Client(
    @Id
    var id: UUID,

    @Column
    var clientName: String,

    @Column
    var clientId: String,

    @Column
    var secretKey: String,

    @Column
    var uri: String,

    @Column
    var isAllowed: Boolean,

    @ManyToOne
    var user: User,
) {

    @PrePersist
    private fun init() {
        id = UUID.randomUUID()
        clientId = clientName + user.id
        secretKey = id.toString() + LocalTime.now().toString();
    }
}
