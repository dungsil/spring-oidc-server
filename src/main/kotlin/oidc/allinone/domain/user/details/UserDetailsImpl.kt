package oidc.allinone.domain.user.details

import oidc.allinone.domain.user.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.04
 */
class UserDetailsImpl(private val _username: String, private val _password: String) : UserDetails {
  override fun getUsername(): String = _username
  override fun getPassword(): String = _password
  override fun getAuthorities(): MutableCollection<out GrantedAuthority> = mutableListOf(SimpleGrantedAuthority("ROLE_USER"))

  override fun isAccountNonLocked(): Boolean = true
  override fun isAccountNonExpired(): Boolean = true

  override fun isCredentialsNonExpired(): Boolean = true

  override fun isEnabled(): Boolean = true

  constructor(user: User) : this(user.username, user.password)
}
