package spring.security.practice.webtoken;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginForm {
    String username;
    String password;
}
