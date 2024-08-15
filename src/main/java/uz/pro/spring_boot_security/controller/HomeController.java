package uz.pro.spring_boot_security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/test")
@RestController
public class HomeController {

    @GetMapping
    public String homePage(){ return "Home page";}

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/user")
    public String userPage(){ return "User page";}

    @PreAuthorize("hasRole('ADMIN')")
    //@PreAuthorize("hasAnyAuthority('','')")
    @GetMapping("/admin")
    public String adminPage(){ return "Admin page";}

    @PreAuthorize("hasRole('MANAGER')")
    @GetMapping("/manager")
    public String managerPage(){ return "Manager page";}
}
