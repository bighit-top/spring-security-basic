package spring.security.securitybasic.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping({"", "/"})
    public String index() {
        //머스테치 기본 폴더: src/main/resources
        //뷰리졸버 설정: templates (prefix), .mustache(suffix) - 생략 가능
        //src/main/resources/templates/index.mustache - WebMvcConfig 설정을 통해 사용
        return "index";
    }

 }