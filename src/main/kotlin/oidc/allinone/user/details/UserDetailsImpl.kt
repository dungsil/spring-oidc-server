package oidc.allinone.user.details

import oidc.allinone.user.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.04
 */
class UserDetailsImpl(val user: User) : UserDetails {
  override fun getUsername(): String = user.username
  override fun getPassword(): String = user.password
  override fun getAuthorities(): MutableCollection<out GrantedAuthority> = mutableListOf(SimpleGrantedAuthority("ROLE_USER"))

  override fun isAccountNonLocked(): Boolean = true
  override fun isAccountNonExpired(): Boolean = true

  override fun isCredentialsNonExpired(): Boolean = true

  override fun isEnabled(): Boolean = true
}
