package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

//	스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
//  login 요청해서 username, password 전송하면(post)
//UsernamePasswordAuthenticationFilter 동작을 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	private final AuthenticationManager authenticationManager;
	
//	login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter: 로그인 시도중");
		
//		1. username, password 받아서
		try {
//			BufferedReader br = request.getReader();
//			String input = null;
//			while((input = br.readLine())!=null) {
//				System.out.println(input);
//			}
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
//			principalDetailsService의 loadByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨
//			DB에 있는 username과 password가 일치한다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken); 
		
//			로그인이 되었다는 뜻			
			PrincipalDetails principalDeatils = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨: " + principalDeatils.getUser().getUsername()); //로그인 정상적으로 되었다는뜻
//			authentication 객체가 session영영게 저장됨 그 방법이 return 해주면 됨
//			리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
//			굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음, 근데 단지 권한 처리때문에 session 넣어 줍니다.
			return authentication;
		} catch (IOException e) {
//			e.printStackTrace();
		}
		System.out.println("==============================");
//		
		return null;
	}
//	 attemptAuthentication 실 요청한 사용자에게 JWT토큰을 response해주면 됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("sucessfulAuthentication 실행됨 : 인증이 완료");
		PrincipalDetails principalDeatils = (PrincipalDetails) authResult.getPrincipal();
		
//		RSA방식은 아니고 Hash 암호방식
		String jwtToken = JWT.create()
				.withSubject("cos토큰")
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000 * 10)))
				.withClaim("id", principalDeatils.getUser().getId())
				.withClaim("username", principalDeatils.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));

		response.addHeader("Authorization", "Bearer" + jwtToken);
	}
}
