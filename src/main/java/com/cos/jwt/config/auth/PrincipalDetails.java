package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * UserDetails Interface.
 * Spring Security(에서) 사용자의 정보를 담는 인터페이스는 UserDetails Interface 이다. 개발자들은 UserDetails Interface Method Override 하여
 * Spring Security(에서) 구현한 클래스(여기서는 PrincipalDetails)을 사용자 정보로 인식하고 인증 작업을 한다. 기본적으로 Override 구현하며, 추가적인 사용자정보
 * 관리가 필요한 경우 멤버변수를 추가하고 getter, setter 한다.
 * Spring Security(에서) 사용자 인증, 인가 등 관련 작업들을 진행한다.
 * UserDetails Interface(는) VO(Value Object) 역할을 한다고 보면 된다.
 *
 * UserDetails Interface(를) implements 하여 PrincipalDetails Class(를) 생성하고, Override Method(를) 구현한다.
 *  1) getAuthorities() : 계정이 갖고 있는 권한 목록을 리턴한다. (ex. User Table Role Column(ROLE_USER, ROLE_ADMIN..) )
 *  2) getPassword() : 계정의 비밀번호를 리턴한다.
 *  3) getUsername() : 계정의 이름을 리턴한다. (ex. User Table -> username or email or userid)
 *  4) isAccountNonExpired() : 계정이 만료되지 않았는지 리턴한다.(true: 만료안됨)
 *  5) isAccountNonLocked() : 계정이 잠겨있지 않았는지 리턴한다.(true: 잠기지 않음)
 *  6) isCredentialNonExpired() : 비밀번호가 만료되지 않았는지 리턴한다.(true: 만료안됨)
 *  7) isEnable() : 계정이 활성화(사용가능)인지 리턴한다.(true: 활성화)
 */
@Data
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(user->{
            authorities.add(()->user);
        });
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
