package uz.pro.spring_boot_security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletOutputStream;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import uz.pro.spring_boot_security.dto.AppErrorDto;
import uz.pro.spring_boot_security.service.user.AuthService;

import java.time.LocalDateTime;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthService authService;

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint(){
        return ((request, response, authException) -> {
            authException.printStackTrace();
            String errorPath = request.getRequestURI();
            String errorMessage = authException.getMessage();
            Integer errorCode = 401;
            AppErrorDto appErrorDto = new AppErrorDto(
                    errorPath,errorMessage,errorCode, LocalDateTime.now()
            );
            response.setStatus(errorCode);
            ServletOutputStream outputStream = response.getOutputStream();
            objectMapper.writeValue(outputStream,appErrorDto);
        });
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        return ((request, response, accessDeniedException) -> {
            accessDeniedException.printStackTrace();
            String errorPath = request.getRequestURI();
            String errorMessage = accessDeniedException.getMessage();
            Integer errorCode = 403;
            AppErrorDto appErrorDto = new AppErrorDto(
                    errorPath,errorMessage,errorCode, LocalDateTime.now()
            );
            response.setStatus(errorCode);
            ServletOutputStream outputStream = response.getOutputStream();
            objectMapper.writeValue(outputStream,appErrorDto);
        });
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/auth/**","/api/test")
                .permitAll()
                .anyRequest()
                .fullyAuthenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .httpBasic()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler())
                .and()
                .addFilterBefore(new JwtTokenFilter(jwtTokenUtil,authService), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /*@Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.builder()
                .username("user")
                .password("123")
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("123")
                .roles("ADMIN")
                .build();
        UserDetails manager = User.builder()
                .username("manager")
                .password("123")
                .roles("MANAGER")
                .build();
        return new InMemoryUserDetailsManager(user,admin,manager);
        return
    }

//    @Bean
//    public AuthenticationProvider authenticationProvider(){
//        var daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
//        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
//        return daoAuthenticationProvider;
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(authenticationProvider());
    }*/

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(List.of(
                "http//localhost:8080"
        ));
        corsConfiguration.setAllowedHeaders(List.of(
                "Accept"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",corsConfiguration);
        /*source.registerCorsConfiguration("/api/v2/**",corsConfiguration2);
        source.registerCorsConfiguration("/api/v3/**",corsConfiguration3);*/
        return source;
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity httpSecurity) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder
                = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(authService)
                .passwordEncoder(passwordEncoder());
        return authenticationManagerBuilder.build();
    }
}
