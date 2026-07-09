package com.duong.Jwt_spring.security;

import com.duong.Jwt_spring.entity.Users;
import com.duong.Jwt_spring.security.CustomUserDetails;
import com.duong.Jwt_spring.security.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // Bước 1: Lấy vé (Token) từ túi khách hàng (Request)
            String jwt = parseJwt(request);

            // Bước 2: Máy soi vé hoạt động
            if (jwt != null && jwtUtils.validateToken(jwt)) {

                // Bước 3: Bóc thông tin từ vé (Không chọc Database)
                String email = jwtUtils.getEmailFromToken(jwt);
                String role = jwtUtils.getRoleFromToken(jwt);

                // Bước 4: Tự "dập" một chiếc thẻ căn cước nội bộ từ thông tin trên vé
                Users fakeUser = new Users();
                fakeUser.setEmail(email);
                fakeUser.setRole(role);
                CustomUserDetails userDetails = new CustomUserDetails(fakeUser);

                // Bước 5: Đóng mộc xanh và lưu vào bộ nhớ tòa nhà
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null, // Mật khẩu để null vì đã xác thực qua Token rồi
                                userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            System.out.println("Không thể thiết lập xác thực người dùng: " + e.getMessage());
        }

        // Bước 6: Mở barie cho đi tiếp
        filterChain.doFilter(request, response);
    }

    // Hàm phụ trợ: Lấy token chuẩn từ Header
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        // Token chuẩn phải bắt đầu bằng chữ "Bearer "
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7); // Cắt bỏ 7 ký tự đầu lấy cái lõi
        }
        return null;
    }
}
