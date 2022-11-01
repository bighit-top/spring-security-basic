package spring.security.securitybasic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //활성화: 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //@Secured 어노테이션 활성화: 특정 메서드에 Secured 하고 싶을 경우 사용, @PreAuthorize, @PostAuthorize 어노테이션 활성화
public class SecurityConfig {

    /* password 암호화 */
    @Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

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
//                .usernameParameter("something") //UserDetailsService loadUserByUsername 메서드 파라미터 이름과 다른 경우 설정
                .loginProcessingUrl("/login") // /login 페이지 호출시 시큐리티가 대신 로그인을 진행해줌: /login 컨트롤러가 필요없음
                .defaultSuccessUrl("/");

        return http.build();
    }
}
