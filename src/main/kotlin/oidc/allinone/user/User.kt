package oidc.allinone.user

import jakarta.persistence.*

/**
 * 사용자 엔티티
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.04
 */
@Entity
@Table(name = "users")
@SequenceGenerator(name = "users__seq", initialValue = 1001, allocationSize = 1)
class User(

  @Id
  @Column(name = "_id")
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "users__seq")
  val id: Long = 0,

  @Column(name = "username")
  val username: String,

  @Column(name = "encrypted_password")
  var password: String
)
