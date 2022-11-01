package spring.security.securitybasic.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.securitybasic.model.User;

//@Repository 어노테이션 없어도 IoC됨 : JpaRepository 를 상속했기 때문
public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username);
}
