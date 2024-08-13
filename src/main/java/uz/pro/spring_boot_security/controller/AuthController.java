package uz.pro.spring_boot_security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import uz.pro.spring_boot_security.config.JwtTokenUtil;
import uz.pro.spring_boot_security.dto.TokenRequest;
@RequestMapping("/api/auth")
@RestController
@RequiredArgsConstructor
public class AuthController {
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
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

}
