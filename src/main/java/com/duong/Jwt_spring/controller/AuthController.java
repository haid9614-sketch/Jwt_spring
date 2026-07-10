package com.duong.Jwt_spring.controller;

import com.duong.Jwt_spring.dto.JwtResponse;
import com.duong.Jwt_spring.dto.LoginRequest;
import com.duong.Jwt_spring.dto.MessageResponse;
import com.duong.Jwt_spring.dto.RegisterRequest;
import com.duong.Jwt_spring.entity.Users;
import com.duong.Jwt_spring.repository.UsersRepository;
import com.duong.Jwt_spring.security.CustomUserDetails;
import com.duong.Jwt_spring.security.CustomUserDetailsService;
import com.duong.Jwt_spring.security.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor // Thay thế @Autowired cho code gọn gàng, đồng bộ
public class AuthController {

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // 1. Giao cho Trưởng phòng xác thực kiểm tra
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            // 2. Lấy đối tượng User đã xác thực thành công ra
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

            // 3. Rèn thẻ Token
            String token = jwtUtils.generateToken(userDetails);

            // 4. Lấy dữ liệu TRỰC TIẾP từ userDetails (Không tốn CPU bóc token nữa)
            String email = userDetails.getUsername();
            String fullName = userDetails.getUser().getFullName();
            String role = userDetails.getAuthorities().iterator().next().getAuthority(); // Lấy quyền đầu tiên

            // Nếu JwtResponse của bạn có @AllArgsConstructor thì dùng luôn thế này cho nhanh:
            JwtResponse jwtResponse = new JwtResponse(token, email, fullName, role);

            return ResponseEntity.ok(jwtResponse);

        } catch (BadCredentialsException e) {
            // Mẹo nhỏ: Trả về mã 401 (UNAUTHORIZED) sẽ chuẩn RESTful hơn là 400 (BAD REQUEST) cho lỗi sai mật khẩu
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Sai email hoặc mật khẩu!"));
        }
    }

    // ham dang ki
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        Optional<Users> user = usersRepository.findByEmail(registerRequest.getEmail());
        if(user.isPresent()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email da ton tai"));
        }
        String hashPass = passwordEncoder.encode(registerRequest.getPassword());
        Users newUser = new Users();

        newUser.setEmail(registerRequest.getEmail());
        newUser.setFullName(registerRequest.getFullName());
        newUser.setPassword(hashPass);
        usersRepository.save(newUser);

        return ResponseEntity.ok(new MessageResponse("Dang ky tai khoan thang cong !!!"));
    }

}
