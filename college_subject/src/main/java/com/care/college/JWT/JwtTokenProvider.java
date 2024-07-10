package com.care.college.JWT;


import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

//JWT 토큰 생성, 검증, 정보 추출 등을 처리하는 클래스
@Log4j2
@Component
public class JwtTokenProvider {
	
	@Value("${jwt.secret}")
    private String secretKey;


    /**
     * 유효한 토큰인지 확인 해주는 메서드
     *
     * @param token String  : 토큰
     * @return boolean      : 유효한지 여부 반환
     */
    public boolean isValidToken(String token) {
    	try {
    		Claims claims = getClaimsFormToken(token);
    		
    		log.info("expireTime :" + claims.getExpiration());
    		log.info("student_No :" + claims.getSubject());
    		Object nameClaim = claims.get("Name");
    		if (nameClaim != null) {
    			log.info("Name :" + nameClaim.toString());
    		} else {
    			log.info("Name : (not available in claims)");
    		}
    		return true;
    	} catch (ExpiredJwtException exception) {
    		log.error("Token Expired");
    		return false;
    	} catch (JwtException exception) {
    		log.error("Token Tampered");
    		return false;
    	} catch (NullPointerException exception) {
    		log.error("Token is null");
    		return false;
    	}
    }

/**
 * Header 내에 토큰을 추출합니다.
 *
 * @param header 헤더
 * @return String
 */
public String getTokenFromHeader(String header) {
    if (header != null && header.startsWith("BEARER ")) {
        return header.substring(7); // "Bearer " 이후의 부분이 토큰.
    }
    return null;
}

    /**
     * 토큰의 만료기간을 지정하는 함수
     *
     * @return Calendar
     */
    private Date createExpiredDate() {
        // 토큰 만료시간은 30일으로 설정
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, 30);  // 5분
        // c.add(Calendar.DATE, 1);         // 1일
        return c.getTime();
    }
    private Map<String, Object> createHeader() {
        Map<String, Object> header = new HashMap<>();

        header.put("typ", "JWT");
        header.put("alg", "HS256");

        return header;
    }



    /**
     * 토큰 정보를 기반으로 Claims 정보를 반환받는 메서드
     *
     * @param token : 토큰
     * @return Claims : Claims
     */
    private Claims getClaimsFormToken(String token) {
        return Jwts.parserBuilder()
        			.setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
        			.build()
        			.parseClaimsJws(token)
        			.getBody();
    }

    /**
     * 토큰을 기반으로 Subject를 반환 해주는 메서드
     *
     * @param token String : 토큰
     * @return String : 사용자 정보
     */
    public String parseTokenToName(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("Name").toString();
    }
    /**
     * 토큰을 기반으로 사용자 정보를 반환받는 메서드
     *
     * @param token : 토큰
     * @return String : 사용자 아이디
     */
    public String getUserIdFromToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("sub").toString();
    }



}
