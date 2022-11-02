package spring.security.securitybasic.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import spring.security.securitybasic.config.auth.PrincipalDetails;
import spring.security.securitybasic.model.User;
import spring.security.securitybasic.repository.UserRepository;

@Controller
@Slf4j
@RequiredArgsConstructor
public class IndexController {

    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /** Authentication 객체가 가질 수 있는 2가지 타입 테스트 - 일반 로그인
     * - Authentication
     * - @AuthenticationPrincipal PrincipalDetails : 어노테이션
     */
    @GetMapping("/test/login")
    public @ResponseBody String testLogin(
            Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails userDetails) {
        log.info("/test/login");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication: {}", ((PrincipalDetails) authentication.getPrincipal()).getUser());

        log.info("userDetails: {}", userDetails.getUser());
        return "일반 세션 정보 확인";
    }

    /** Authentication 객체가 가질 수 있는 2가지 타입 테스트 - OAuth2 로그인
     * - Authentication
     * - @AuthenticationPrincipal OAuth2User : 어노테이션
     */
    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth) {
        log.info("/test/oauth/login");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("authentication: {}", oAuth2User.getAttributes());

        log.info("oauth: {}", oauth.getAttributes());
        return "OAuth 세션 정보 확인";
    }

    @GetMapping({"", "/"})
    public String index() {
        //머스테치 기본 폴더: src/main/resources
        //뷰리졸버 설정: templates (prefix), .mustache(suffix) - 생략 가능
        //src/main/resources/templates/index.mustache - WebMvcConfig 설정을 통해 사용
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("PrincipalDetails: {}", principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info("username:{}, password:{}, email,{}", user.getUsername(), user.getPassword(), user.getEmail());

        user.setRole("ROLE_USER");

        //패스워드를 암호화 하지 않으면 스프링 시큐리티를 사용할 수 없음 -> Bcrypt 암호화
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);

        userRepository.save(user);

        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    //@PostAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") //data() 메서드 실행 후 확인
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") //data() 메서드 실행 전 확인
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터정보";
    }
}