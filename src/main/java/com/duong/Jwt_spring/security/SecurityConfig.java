package com.duong.Jwt_spring.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // Gọi Anh bảo vệ mà bạn vừa tạo lúc nãy vào đây
    private final AuthTokenFilter authTokenFilter;

    // 1. Máy băm mật khẩu (Dùng thuật toán BCrypt cực mạnh)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. Cấp quyền cho Trưởng phòng bảo vệ (AuthenticationManager)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // 3. Nội quy Tòa nhà (Thiết lập các tuyến phòng thủ)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable()) // Tắt CSRF (Bảo vệ chống giả mạo) vì hệ thống JWT tự miễn nhiễm với lỗi này

                // Ép hệ thống chạy ở chế độ Phi trạng thái (Stateless) - Không lưu Session
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Phân luồng đường đi
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/auth/**").permitAll() // Thả cửa (không cần vé) cho các API bắt đầu bằng /api/auth (Đăng ký, Đăng nhập)
                                .anyRequest().authenticated() // TẤT CẢ các đường dẫn khác đều bị khóa, bắt buộc phải trình vé Token
                );

        // Điều động Anh bảo vệ (AuthTokenFilter) lên đứng chặn ngay trước cửa kiểm tra mặc định của Spring
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

