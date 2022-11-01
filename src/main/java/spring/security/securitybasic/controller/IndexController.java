package spring.security.securitybasic.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
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

    @GetMapping({"", "/"})
    public String index() {
        //머스테치 기본 폴더: src/main/resources
        //뷰리졸버 설정: templates (prefix), .mustache(suffix) - 생략 가능
        //src/main/resources/templates/index.mustache - WebMvcConfig 설정을 통해 사용
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user() {
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