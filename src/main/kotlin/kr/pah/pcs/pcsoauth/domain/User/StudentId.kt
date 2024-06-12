package kr.pah.pcs.pcsoauth.domain.User

import jakarta.persistence.*
import kr.pah.pcs.pcsoauth.domain.model.Grade
import lombok.Builder
import lombok.Getter

@Entity
@Builder
@Getter
class StudentId {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private val idx: Int? = null

    @Column
    private var grade: Grade? = null

    @Column
    private var studentId: String? = ""

    @ManyToOne
    @JoinColumn(name = "users_id")
    private val user: User?  =null
}
