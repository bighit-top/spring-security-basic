package spring.security.securitybasic.config.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import spring.security.securitybasic.model.User;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 시큐리티가 /login 주소 요청이 오면 대신 로그인을 진행시킨다.
 * 로그인 진행이 완료되면 session 을 만들어 준다.: Security ContextHolder
 * Security 가
 * -> Security Session 영역을 생성하고
 * -> session은 Authentication 의 객체 타입을 받고
 * -> Authentication 객체 안에 User 정보를 담은 UserDetails 타입 객체를 받음
 * => Security Session(Authentication(UserDetails))
 */
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    /* 해당 User의 권한을 리 */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /* 계정 만료 여부 */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /* 계정 잠김 여부 */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /* 계정 인증 보안 만료 여부?: 비밀번호 사용 사용 기간 등 */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        //만약 회원이 1년동안 로그인을 안했을 때, 휴면계정 처리 한다 등의 로직을 처리함
        return true;
    }
}