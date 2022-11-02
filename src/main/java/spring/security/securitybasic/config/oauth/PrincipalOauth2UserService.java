package spring.security.securitybasic.config.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import spring.security.securitybasic.config.auth.PrincipalDetails;
import spring.security.securitybasic.config.oauth.provider.GoogleUserInfo;
import spring.security.securitybasic.config.oauth.provider.NaverUserInfo;
import spring.security.securitybasic.config.oauth.provider.OAuth2UserInfo;
import spring.security.securitybasic.model.User;
import spring.security.securitybasic.repository.UserRepository;

import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * oauth2 login 후 userRequest 데이터에 대한 후 처리
     * userRequest 정보: 구글 로그인 버튼 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
     *  - code를 받아서 accessToken을 응답 받는 객체
     * loadUser함수: userRequest 데이터에 대한 후처리 함수
     * 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어짐
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        //code를 통해 구성한 정보
        log.info("OAuth2UserRequest.userRequest: {}", userRequest.getClientRegistration()); //어떤 OAuth 인지 확인 가능
        log.info("OAuth2UserRequest.userRequest: {}", userRequest.getAccessToken());
        //token을 통해 응답받은 회원정보
        log.info("oAuth2User: {}", oAuth2User );

//        //회원가입
//        String provider = userRequest.getClientRegistration().getClientId(); //구글
//        String providerId = oAuth2User.getAttribute("sub");
//        String username = provider + "_" + providerId;
//        String password = bCryptPasswordEncoder.encode("1234");
//        String email = oAuth2User.getAttribute("email");
//        String role = "ROLE_USER";
//
//        User findUser = userRepository.findByUsername(username);
//        if (findUser == null) {
//            findUser = User.builder()
//                    .username(username)
//                    .password(password)
//                    .email(email)
//                    .role(role)
//                    .provider(provider)
//                    .providerId(providerId)
//                    .build();
//            userRepository.save(findUser);
//        }
//
//        return new PrincipalDetails(findUser, oAuth2User.getAttributes());

        return processOAuth2User(userRequest, oAuth2User);
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {

        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("google 로그인");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }
        if (userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            log.info("naver 로그인");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }

        Optional<User> userOptional = userRepository.findByProviderAndProviderId(oAuth2UserInfo.getProvider(), oAuth2UserInfo.getProviderId());

        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            user.setEmail(oAuth2UserInfo.getEmail()); //있으면 update
            userRepository.save(user);
        } else {
            //OAuth 유저는 패스워드가 null이기 때문에 일반 로그인을 할 수 없음
            user = User.builder()
                    .username(oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId())
                    .email(oAuth2UserInfo.getEmail())
                    .role("ROLE_USER")
                    .provider(oAuth2UserInfo.getProvider())
                    .providerId(oAuth2UserInfo.getProviderId())
                    .build();
            userRepository.save(user);
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
