package com.vn.springsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
public class HelloController {

    @GetMapping("")
    public ResponseEntity<String> hello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Authentication class: " + authentication.getClass().getName());
        System.out.println("Authentication details: " + authentication.getDetails());
        System.out.println("Authentication authorities: " + authentication.getAuthorities());
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/private")
    public ResponseEntity<String> getPrivateContent() {
        return ResponseEntity.status(HttpStatus.OK).body("Private content");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> getAdmin() {
        return ResponseEntity.ok("Admin");
    }
}
