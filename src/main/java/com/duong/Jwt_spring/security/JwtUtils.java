package com.duong.Jwt_spring.security;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;


@Component
public class JwtUtils {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpiration;

    private Key getSignKey() {
        byte[] keyBytes = this.jwtSecret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // tao token - nhet het thong tin vao token
    public String generateToken(CustomUserDetails userDetails) {
        String role = userDetails.getAuthorities().iterator().next().getAuthority();
        return Jwts.builder()
                .setSubject(userDetails.getUsername()) // loi chua email, thong tin duy nhat de dang nhap
                .claim("role", role)
                .claim("fullName", userDetails.getUser().getFullName())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ham boc gmail
    public String getEmailFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey()) // tu truyen key vao de kiem tra key
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
    // ham boc full name
    public String getFullNameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey()) // tu truyen key vao de kiem tra key
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("fullName", String.class);
    }
    // boc role
    public String getRoleFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("role", String.class); // Lấy giá trị của key "role" ép kiểu về String
    }

    // Hàm kiểm tra tính hợp lệ
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(authToken);
            return true;
        } catch (Exception e) {
            System.out.println("Token không hợp lệ: " + e.getMessage());
        }
        return false;
    }
}