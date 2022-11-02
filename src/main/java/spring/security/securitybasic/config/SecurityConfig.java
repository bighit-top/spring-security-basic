package spring.security.securitybasic.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import spring.security.securitybasic.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity //활성화: 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //@Secured 어노테이션 활성화: 특정 메서드에 Secured 하고 싶을 경우 사용, @PreAuthorize, @PostAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    /* password 암호화 */
//    @Bean
//    public BCryptPasswordEncoder encodePassword() {
//        return new BCryptPasswordEncoder();
//    }

    /* spring security filter 설정 */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                        .antMatchers("/user/**").authenticated() //인증만
                        .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER', 'ROLE_ADMIN')") //권한 필요
                        .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll()
                        .and()
                        .formLogin()
                        .loginPage("/loginForm")
//                        .usernameParameter("something") //UserDetailsService loadUserByUsername 메서드 파라미터 이름과 다른 경우 설정
                        .loginProcessingUrl("/login") // /login 페이지 호출시 시큐리티가 대신 로그인을 진행해줌: /login 컨트롤러가 필요없음
                        .defaultSuccessUrl("/")
                        .and() //OAuth2
                        .oauth2Login()
                        .loginPage("/loginForm") //구글 로그인이 완료된 뒤의 후처리가 필요
                                                //1.코드받기(인증), 2.엑세스토큰(권한), 3.사용자프로필 정보를 가져오고, 4.그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
                                                // 쇼핑몰 : 구글(이메일, 전화번호, 이름, 아이디) -> 집주소 추가 정보 필요
                                                // 백화점몰 : vip등급, 일반등금 등 추가 정보 필요
                                                // 추가 정보가 필요 없으면 자동 회원가입 처리 가능
                        .userInfoEndpoint() //후처리: 코드로 받은게 아님. 엑세스토큰+사용자프로필 정보
                        .userService(principalOauth2UserService);

        return http.build();
    }
}
