package com.vn.springsecurity.controller;

import com.vn.springsecurity.dto.request.AuthenticationRequest;
import com.vn.springsecurity.dto.request.RegisterRequest;
import com.vn.springsecurity.dto.response.AuthenticationResponse;
import com.vn.springsecurity.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        AuthenticationResponse response = authenticationService.register(registerRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@Valid @RequestBody AuthenticationRequest authenticationRequest) {
        AuthenticationResponse response = authenticationService.authenticate(authenticationRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken (HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthenticationResponse authenticationResponse = authenticationService.refreshToken(request, response);
        return ResponseEntity.ok(authenticationResponse);
    }
}
