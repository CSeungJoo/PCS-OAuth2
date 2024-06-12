package kr.pah.pcs.pcsoauth.domain.User

import jakarta.persistence.*
import kr.pah.pcs.pcsoauth.domain.model.Role
import java.time.LocalDate

@Entity
@Table(name = "users")
class User(
    @Id
    var id: String,

    @Column
    var username: String,

    @Column
    var password: String,

    @Column
    var email: String,

    @Column
    var birth: LocalDate,

    @Column
    var phone: String,

    @Column
    @Enumerated(EnumType.STRING)
    var role: Role


) {
}