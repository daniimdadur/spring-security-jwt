package spring.security.practice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import spring.security.practice.model.MyUserDetailService;
import spring.security.practice.webtoken.JwtService;
import spring.security.practice.webtoken.LoginForm;

@RestController
public class ContentController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private MyUserDetailService myUserDetailService;

    @GetMapping("/home")
    public String handleWelcome() {
        return "home";
    }

    @GetMapping("/admin/home")
    public String handleAdminHome() {
        return "home_admin";
    }

    @GetMapping("/user/home")
    public String handleUserHome() {
        return "home_user";
    }

    @PostMapping("/authenticate")
    public String handleAuthentication(@RequestBody LoginForm loginForm) {
        Authentication authentication = this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginForm.getUsername(), loginForm.getPassword()
        ));
        if (authentication.isAuthenticated()) {
            return this.jwtService.generateToken(this.myUserDetailService.loadUserByUsername(loginForm.getUsername()));
        } else {
            throw new UsernameNotFoundException("invalid credentials");
        }
    }
}
