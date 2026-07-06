package com.duong.Jwt_spring.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @Email(message = "email khong dung dinh dang")
    private String email;

    @Size(min = 8, message = " mat khau chua it nhat 8 ki tu")
    private String password;

    @NotBlank(message = "Ten khong duoc de trong")
    private String fullName;
}
