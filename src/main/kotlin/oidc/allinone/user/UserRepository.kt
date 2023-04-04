package oidc.allinone.user

import org.springframework.data.jpa.repository.JpaRepository

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.04
 */
interface UserRepository : JpaRepository<User, Long> {
  fun findByUsername(username: String): User?
}
