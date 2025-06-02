package com.vn.springsecurity;

import com.vn.springsecurity.enums.Role;
import com.vn.springsecurity.model.User;
import com.vn.springsecurity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner (PasswordEncoder passwordEncoder, UserRepository userRepository) {
        return args -> {
            // Code to run on application startup
            System.out.println("Application started successfully!");

            User admin = User.builder()
                    .email("admin@email.com")
                    .password(passwordEncoder.encode("password"))
                    .firstName("Admin")
                    .lastName("User")
                    .role(Role.ADMIN)
                    .provider("local".toUpperCase())
                    .build();
            userRepository.save(admin);

            User manager = User.builder()
                    .email("manager@email.com")
                    .password(passwordEncoder.encode("password"))
                    .firstName("Manager")
                    .lastName("User")
                    .role(Role.MANAGER)
                    .provider("local".toUpperCase())
                    .build();
            userRepository.save(manager);

        };
    }
}
