package uz.pro.spring_boot_security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import uz.pro.spring_boot_security.config.JwtTokenUtil;
import uz.pro.spring_boot_security.dto.TokenRequest;
import uz.pro.spring_boot_security.entity.UserEntity;
import uz.pro.spring_boot_security.service.user.UserService;

@RequestMapping("/api/auth")
@RestController
@RequiredArgsConstructor
public class AuthController {
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    @PostMapping("/login")
    public String token(@RequestBody TokenRequest tokenRequest) {
        String username = tokenRequest.username();
        String password = tokenRequest.password();

        var authentication = new UsernamePasswordAuthenticationToken(username,password);
        authenticationManager.authenticate(authentication);
       /* UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if(!passwordEncoder.matches(password,userDetails.getPassword())) throw new BadCredentialsException("No password?");*/
        return jwtTokenUtil.generateToken(username);
    }

    @PostMapping("/register")
    public UserEntity register(@RequestBody UserEntity userEntity){
        return userService.save(userEntity);
    }

}
