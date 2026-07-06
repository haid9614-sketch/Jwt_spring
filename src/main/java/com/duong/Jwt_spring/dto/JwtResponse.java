package com.duong.Jwt_spring.dto;

import lombok.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String email;
    private String fullName;
    private String role;
}
