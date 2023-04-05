package oidc.allinone.domain.user.details

import oidc.allinone.global.utils.CryptoUtils
import oidc.allinone.global.utils.CryptoUtils.passwordEncoder
import oidc.allinone.domain.user.User
import oidc.allinone.domain.user.UserRepository
import org.springframework.context.annotation.Primary
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.04
 */
@Primary
@Service
class UserDetailsServiceImpl(private val repo: UserRepository) : UserDetailsService {

  init {
    val user = User(username = "local", password = passwordEncoder.encode("secret"))
    repo.saveAndFlush(user)
  }

  override fun loadUserByUsername(username: String?): UserDetails {
    return username
      ?.let { repo.findByUsername(it) }
      ?.let { UserDetailsImpl(it) }
      ?: throw UsernameNotFoundException("User($username) is not found")
  }
}
