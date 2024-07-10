package com.care.college.student;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.care.college.JWT.AuthConstants;
import com.care.college.JWT.JwtTokenProvider;

import jakarta.servlet.http.HttpSession;

@Controller
public class StudentController {
	@Autowired private StudentService service;
	@Autowired private StudentMapper_Student mapper;
	private final JwtTokenProvider JwtTokenProvider;

    @Autowired
    public StudentController(JwtTokenProvider JwtTokenProvider) {
        this.JwtTokenProvider = JwtTokenProvider;
    }

	// 로그인
	@GetMapping("/student/login")
	public String login() {
		
		return "student/login";
	}
	
	//토큰유효성 검증
	@PostMapping("/student/validateToken")
	public ResponseEntity validateToken(@RequestBody Map<String, String> requestBody) {
		String token = requestBody.get("token");
        System.out.println("토큰 : " + token);
        String StorageToken = JwtTokenProvider.getTokenFromHeader(token);
        System.out.println("스토리지 토큰 : "+StorageToken);
		if (StorageToken != null) {
			//가져온 토큰 유효성 체크
			boolean check = JwtTokenProvider.isValidToken(StorageToken);    
	        if (check == false) {
	        	return new ResponseEntity<>("토큰 검증 실패", HttpStatus.UNAUTHORIZED);
	        } else {
	        	Map<String, Object> response = new HashMap<>();
            	HttpHeaders headers = new HttpHeaders();
            	 
 	            headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + StorageToken);	//http헤더로 보내기
 	            String student_no = JwtTokenProvider.getUserIdFromToken(StorageToken); 					//subject 추출
 	        	String name = JwtTokenProvider.parseTokenToName(StorageToken); 							//name 추출

 	        	response.put("student_No", student_no);
 	        	response.put("name", name);
 	            
 	            return new ResponseEntity<>(response, headers, HttpStatus.OK);		// HttpHeaders 및 데이터를 함께 전송
	        }

		}
		return new ResponseEntity<>("토큰이 없습니다.", HttpStatus.UNAUTHORIZED);
	}
	
	@ResponseBody
	@PostMapping("/student/loginProc")
	public ResponseEntity loginProc(@RequestBody Map<String, String> requestBody, 
									StudentDTO_Student studentDTO,
									Model model) {
		
	    String student_no = requestBody.get("student_no");
	    String password = requestBody.get("password");

	    try {
	        // 학번이 숫자로만 구성되어 있는지 확인
	        if (student_no.matches("\\d+")) {
	            int student_No = Integer.parseInt(student_no);

			//학번, 비밀번호 일치여부 확인 후 msg 반환
			String msg = service.loginProc(student_no, password, model);
			//해당 학생 DTO
			studentDTO = mapper.login(student_No);
			System.out.println(msg);
			
			if (msg.equals("로그인 성공")) {
		        // 로그인 성공 시 토큰 생성
		        String tokenInfo = JwtTokenProvider.generateJwtToken(studentDTO);
		        
		        //생성된 토큰 유효성 체크
		        HttpHeaders headers = new HttpHeaders();
		        System.out.println(tokenInfo);
		        boolean check = JwtTokenProvider.isValidToken(tokenInfo);
		        if (check) {        	    
		        	 // 토큰을 응답헤더에 담아 전달(AuthConstants.java변수명)
		            headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + tokenInfo);
		            return new ResponseEntity<>("학생 로그인 성공",headers,HttpStatus.OK);
		        } else {
			        return new ResponseEntity<>("로그인 실패", HttpStatus.UNAUTHORIZED);
			    }
			}  else if (msg.equals("관리자입니다.")) {
		    	// 로그인 성공 시 토큰 생성
		        String tokenInfo = JwtTokenProvider.generateJwtToken(studentDTO);
		        //생성된 토큰 유효성 체크
		        HttpHeaders headers = new HttpHeaders();
		        System.out.println(tokenInfo);
		        boolean check = JwtTokenProvider.isValidToken(tokenInfo);
		        if (check) {        	    
		        	 // 토큰을 응답헤더에 담아 전달(AuthConstants.java변수명)
		            headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + tokenInfo);
		            return new ResponseEntity<>("관리자 로그인 성공",headers,HttpStatus.OK);
	
		        } else {
			        return new ResponseEntity<>("로그인 실패", HttpStatus.UNAUTHORIZED);
			    }
		        
			} else if (msg.equals("학번 또는 비밀번호를 확인 후 다시 입력하세요.")) {
	            return new ResponseEntity<>("학번 또는 비밀번호를 확인 후 다시 입력하세요.",HttpStatus.OK);
				
			} else if (msg.equals("비밀번호를 변경해주세요.")) {
	
		        // 로그인 성공 시 토큰 생성
		        String tokenInfo = JwtTokenProvider.generateJwtToken(studentDTO);
		        //생성된 토큰 유효성 체크
		        HttpHeaders headers = new HttpHeaders();
		        System.out.println(tokenInfo);
		        boolean check = JwtTokenProvider.isValidToken(tokenInfo);
		        if (check) {        	    
		        	 // 토큰을 응답 본문에 담아 전달
		            headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + tokenInfo);
		            return new ResponseEntity<>("비밀번호를 변경해주세요.",headers,HttpStatus.OK);
		        } else {
			        return new ResponseEntity<>("로그인 실패", HttpStatus.UNAUTHORIZED);
			    }
			}
			
			return new ResponseEntity<>("로그인 실패", HttpStatus.UNAUTHORIZED);
		
	        } else {
	        	return new ResponseEntity<>("학번은 숫자로 입력하세요.",HttpStatus.OK);
	        }
	    } catch (NumberFormatException e) {
	    	return new ResponseEntity<>("학번 또는 비밀번호를 확인 후 다시 입력하세요.",HttpStatus.OK);
	    }
	}
    //로그인 체크
    @ResponseBody   
    @PostMapping("/student/tokenCheck")
    public ResponseEntity loginCheck(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
          Model model) {
       System.out.println("토큰"+token);
       if (token != null && token.startsWith("BEARER ")) {
          String jwtToken = token.substring(7);                   // "Bearer " 이후의 부분
          boolean check = JwtTokenProvider.isValidToken(jwtToken);   // 여기서 jwtToken을 검증하고 필요한 작업 수행
          if (check) {
             Map<String, Object> response = new HashMap<>();
             HttpHeaders headers = new HttpHeaders();
             
             headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + jwtToken);   //http헤더로 보내기
             String name = JwtTokenProvider.parseTokenToName(jwtToken);                      //name 추출
             
             response.put("name", name);
             var authorizationHeader = headers.getFirst(AuthConstants.AUTH_HEADER);
             // response.headers에서 'Authorization' 헤더를 가져온다.
             
             return new ResponseEntity<>(response, headers, HttpStatus.OK);      // HttpHeaders 및 데이터를 함께 전송
             
          } else {
             return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
          }
       }
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");
    }
	@GetMapping("/student/myInfo")
	public String myInfom() {
		return "student/myInfo";
	}
	@ResponseBody
	@PostMapping("/student/myInfo")
    public ResponseEntity myInfo(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
    		StudentDTO_Student student, String postcode, String address, String detailAddress, Model model) {
		System.out.println("토큰"+token);
		if (token != null && token.startsWith("BEARER ")) {
        	
            String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
            // 여기서 jwtToken을 검증하고 필요한 작업 수행
            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            if (check) {
            	Map<String, Object> response = new HashMap<>();

            	String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
        		int student_No = Integer.parseInt(student_no);

        		student = mapper.login(student_No);	
        		
        		address = student.getAddress();
        		if (address != null) {
        			String[] addr = address.split(",");
        			if (addr.length >= 2) {
        				postcode = addr[0];
        				address = addr[1];
        				if (addr.length == 3) {
        					detailAddress = addr[2];
        				}
        			}
        		}
        		response.put("student", student);
            	response.put("postcode", postcode);
            	response.put("address", address);
            	response.put("detailAddress", detailAddress);

            	return ResponseEntity.ok(response);
        		//model.addAttribute("student", student);

            } else {
            	return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");
		}

	@GetMapping("/student/updateInfo")
	public String updateInfom() {
		return "student/updateInfo";
	}
	@ResponseBody
	@PostMapping("/student/updateInfo")
	public ResponseEntity updateInfo(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
									@RequestBody Map<String, String> requestBody,
									Model model, StudentDTO_Student student) {
			String tel = requestBody.get("tel");
			String email = requestBody.get("email");
			String birth = requestBody.get("birth");
			String postcode = requestBody.get("postcode");
			String address = requestBody.get("address");
			String detailAddress = requestBody.get("detailAddress");
			if (token != null && token.startsWith("BEARER ")) {
	        	System.out.println("토큰"+token);
	            String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
	            // 여기서 jwtToken을 검증하고 필요한 작업 수행
	            boolean check = JwtTokenProvider.isValidToken(jwtToken);
	            if (check) {
		        	HttpHeaders headers = new HttpHeaders();
		            headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + jwtToken);
	            	String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
	            	student.setStudent_No(Integer.parseInt(student_no));
					student.setTel(tel);
					student.setEmail(email);
					student.setBirth(birth);
					student.setAddress(postcode + "," + address + "," + detailAddress);
					String msg = service.updateInfo(student);
					System.out.println(msg);
					if (msg.equals("학생정보 수정 완료")) {
						return new ResponseEntity<>("토큰 검증 성공",headers,HttpStatus.OK);
					}
		        	return new ResponseEntity<>("토큰 검증 실패", HttpStatus.UNAUTHORIZED);
		        } else {
			        
		        	return new ResponseEntity<>("토큰 검증 실패", HttpStatus.UNAUTHORIZED);

				}
            }
			return new ResponseEntity<>("토큰이 없습니다.", HttpStatus.UNAUTHORIZED);
		}

	
	@GetMapping("/student/changePw")
	public String changePw() {
		return "student/changePw";
	}
	@ResponseBody
	@PostMapping("/student/changePwProc")
	public ResponseEntity changePwProc(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
								@RequestBody Map<String, String> requestBody,
								StudentDTO_Student student, Model model) { 
		String beforePw = requestBody.get("beforePw");
		String pw = requestBody.get("pw");
		if (token != null && token.startsWith("BEARER ")) {
        	
            String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
            // 여기서 jwtToken을 검증하고 필요한 작업 수행
            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            if (check) {
            	String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
            	student = service.myInfo(Integer.parseInt(student_no));

				//초기비번이 아닐때
				if (student.getPassword().length() >= 8 ) {
					BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
					if(encoder.matches(beforePw, student.getPassword()) == true) {
						//입력받은 현재비밀번호 == 실제 현재비밀번호
						String msg = service.changePw(student, pw);
						System.out.println(msg);
						if (msg.equals("비밀번호가 변경되었습니다.")) {
							return new ResponseEntity<>("비밀번호가 변경되었습니다. 다시 로그인 해주세요.",HttpStatus.OK);
						} else {
				        	return new ResponseEntity<>("다시 입력해주세요.",HttpStatus.OK);
						}
					}else {
			        	return new ResponseEntity<>("비밀번호가 다릅니다.",HttpStatus.OK);
					}
				} else {
					if(beforePw.equals(student.getPassword())) {
						//입력받은 현재비밀번호 == 실제 현재비밀번호
						String msg = service.changePw(student, pw);
		
						if (msg.equals("비밀번호가 변경되었습니다.")) {
							return new ResponseEntity<>("비밀번호가 변경되었습니다. 다시 로그인 해주세요.",HttpStatus.OK);
						} else {
				        	return new ResponseEntity<>("다시 입력해주세요.",HttpStatus.OK);
						}
					}else {
			        	return new ResponseEntity<>("비밀번호가 다릅니다.",HttpStatus.OK);
					}
				}

            }
			return new ResponseEntity<>("다시 로그인 해주세요.", HttpStatus.UNAUTHORIZED);
		}
		return new ResponseEntity<>("토큰이 없습니다.", HttpStatus.UNAUTHORIZED);

	}
	
	//신입생 학번조회
	@GetMapping("/student/searchStNum")
	public String searchStNum(String name, String student_no, Model model) {
		return "student/searchStNum";
	}
	@PostMapping("/student/searchStNum")
	public String searchStNum(@RequestParam(name = "name") String name,
							@RequestParam(name = "department") String department,
							@RequestParam(name = "tel") String tel, 
							Model model) {

		int student_no = service.searchStNum(name, department,tel,model);
		if(student_no==0)
			return "alert";
		model.addAttribute("name",name);
		model.addAttribute("student_no",student_no);
		return "student/searchSt";
	}
	


}
