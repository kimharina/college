package com.care.college.subject;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.care.college.JWT.AuthConstants;
import com.care.college.JWT.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

@Controller
public class Subject_Controller {

   @Autowired private Subject_Service service;
   @Autowired private Subject_Mapper mapper;
   private final JwtTokenProvider JwtTokenProvider;
   private String targetDateTime;
   private String endTargetDateTime;

    @Autowired
    public Subject_Controller(JwtTokenProvider JwtTokenProvider) {
        this.JwtTokenProvider = JwtTokenProvider;
    }
    
    //로그인 체크
    @ResponseBody   
    @PostMapping("/sugang/loginCheck")
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
    
   //옆 sideBar - 로그아웃(토큰값 가져와서 출력)
   @ResponseBody   
   @PostMapping("/sugang/validate")
    public ResponseEntity validate(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                              Model model) {
      System.out.println("토큰"+token);
      if (token != null && token.startsWith("BEARER ")) {
            String jwtToken = token.substring(7);                   // "Bearer " 이후의 부분
            boolean check = JwtTokenProvider.isValidToken(jwtToken);   // 여기서 jwtToken을 검증하고 필요한 작업 수행
            if (check) {
               Map<String, Object> response = new HashMap<>();
               HttpHeaders headers = new HttpHeaders();
                
                headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + jwtToken);   //http헤더로 보내기
                String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);                //student_no 추출
               String name = JwtTokenProvider.parseTokenToName(jwtToken);                      //name 추출

               response.put("student_No", student_no);
               response.put("name", name);
                var authorizationHeader = headers.getFirst(AuthConstants.AUTH_HEADER); 
                	// response.headers에서 'Authorization' 헤더를 가져옴
                
                return new ResponseEntity<>(response, headers, HttpStatus.OK);      // HttpHeaders 및 데이터를 함께 전송

            } else {
               return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
            }
        }
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");
   }
   
   //수강신청 페이지
   @RequestMapping("/sugang/sugang")
   public String sugang() {
      return "/sugang/sugang";

   }
   
   //sugang.jsp - 과목코드로 신청(검색)
    @PostMapping("/sugang/search")
    @ResponseBody
   public ResponseEntity search( 
               @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
               @RequestBody Map<String, String> requestBody, Model model ) {
       String search = requestBody.get("search");
      String select = requestBody.get("select");
       System.out.println("토큰"+token);
       System.out.println("search : "+search);
      if (token != null && token.startsWith("BEARER ")) {
           
            String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
            
            // 여기서 jwtToken을 검증하고 필요한 작업 수행
            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            
            if (check) {
               String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
             List<Subject_DTO> subjects = service.searchCart(search, select, student_no);
             return new ResponseEntity<>(subjects, HttpStatus.OK);
            }
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
      }
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");

    }
    
  

    //sugang.jsp - 과목코드로 신청(신청 버튼)
    @PostMapping("/sugang/sugang")
    @ResponseBody
   public String sugang( 
               @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
               @RequestBody Map<String, String> requestBody, Model model ) {
       String subject_No = requestBody.get("subjectNo");
       System.out.println("과목코드" + subject_No);
       
       System.out.println("토큰" + token);
       if (token != null && token.startsWith("BEARER ")) {

           String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
           // 여기서 jwtToken을 검증하고 필요한 작업 수행
           boolean check = JwtTokenProvider.isValidToken(jwtToken);
           if (check) {
              String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);    //student_no 추출
               String name = JwtTokenProvider.parseTokenToName(jwtToken);          //name 추출
               Subject_DTO subjects = mapper.getSubject(Integer.parseInt(subject_No));
              String result = service.saveSugang(student_no, name, subjects);
              
              if(result.equals("같은 시간에 이미 수업이 있습니다.")) 
                 return "같은 시간에 이미 수업이 있습니다.";
              else if(result.equals("신청 완료"))
                 return "신청 완료";
              else if(result.equals("인원이 초과되었습니다."))
                 return "인원이 초과되었습니다.";
              else
                 return "신청 실패";
           }
           System.out.println("토큰이 유효하지 않습니다.");
           return "토큰이 유효하지 않습니다.";
       }

       System.out.println("토큰이 없습니다.");
       return "토큰이 없습니다.";

   }
    
  //sugang.jsp - 관심과목으로 신청(리스트 나타내기)
    @PostMapping("/sugang/request")
    @ResponseBody
    public ResponseEntity<List<Cart_DTO>> requestCart(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
            @RequestBody Map<String, String> requestBody) {

       String subject_No = requestBody.get("subject_No");

        System.out.println("토큰" + token);
        System.out.println("request_subject_No : " + subject_No);

        if (token != null && token.startsWith("BEARER ")) {
            String jwtToken = token.substring(7);

            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            if (check) {
                String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
                List<Cart_DTO> carts = service.requestCart(subject_No, student_no);
                System.out.println("request_subject_No : " + subject_No);
                return new ResponseEntity<>(carts, HttpStatus.OK);
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }
    
  //sugang.jsp - 관심과목으로 신청(취소 버튼)
    @PostMapping("/sugang/delete-endpoint")
    @ResponseBody
    public ResponseEntity<List<Cart_DTO>> deleteCart(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
            @RequestBody Map<String, Integer> requestBody) {

       Integer subject_No = requestBody.get("subject_No");

        System.out.println("토큰" + token);
        System.out.println("delete subject_No : " + subject_No);

        if (token != null && token.startsWith("BEARER ")) {
            String jwtToken = token.substring(7);

            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            if (check) {
                String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
                service.deleteCart(subject_No, student_no); // 삭제하는 부분 

                return new ResponseEntity<>(HttpStatus.OK);
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }
    
    //sugang.jsp - 관심과목으로 신청(수강신청 버튼)
    @ResponseBody
    @PostMapping(value = "/sugang/request_final", produces = "application/json; charset=utf-8")
    public String requestFinal(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                               @RequestBody Map<String, Object> requestBody, Model model) {
        System.out.println("토큰" + token);
        if (token != null && token.startsWith("BEARER ")) {
            String jwtToken = token.substring(7);
            boolean check = JwtTokenProvider.isValidToken(jwtToken);

            if (check) {
                String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
                String Student_Name = JwtTokenProvider.parseTokenToName(jwtToken);   //name 추출
                int student_No = Integer.parseInt(student_no);

                List<Integer> subjectNos = (List<Integer>) requestBody.get("subject_No");

                System.out.println("subjectNos" + subjectNos);
                System.out.println("student_No" + student_No);
                System.out.println("Student_Name" + Student_Name);
                
                for (Integer subject_No : subjectNos) {
                	
             	    // cart_DTO에 있는 데이터를 가져오는 작업 추가
             	    List<Cart_DTO> cartList = service.getCartData(subject_No, student_No, Student_Name);
             	    
             	   // 중복 확인을 위한 작업
                     List<Integer> existingSubjectNos = service.getExistingSubjects(student_No);
                     
                   // 현재 수강하려는 강의가 이미 수강한 강의인지 확인
                     if (existingSubjectNos.contains(subject_No)) {
                         System.out.println("과목 번호 " + subject_No + "번은 이미 수강한 강의입니다. 건너뜁니다.");
                         continue;
                     }else {
                    	 Subject_DTO subjects = mapper.getSubject(subject_No);
 	                    // subject_schedule_db에 데이터 추가
 	                    String res = service.addToSubjectSchedule(cartList, subjects, student_No, Student_Name);
  
 	                    if (res.equals("신청 완료!")) {
 	                    	mapper.studentPlus(subjects.getSubject_No());
 	                        System.out.println("과목 번호 " + subject_No + "번이 subject_schedule_db에 추가되었습니다.");
 	                    } else if(res.equals("인원이 마감되었습니다.")){
 	                       System.out.println("과목 번호 " + subject_No + "번 subject_schedule_db에 추가 실패");
 	                       return subject_No +"번은 인원이 마감되었습니다.";
 	                    } else if(res.equals("겹치는 시간이 있습니다.")){
  	                       System.out.println("과목 번호 " + subject_No + "번 subject_schedule_db에 추가 실패");
  	                       return subject_No +"번은 같은 시간대에 이미 과목이 있습니다.";
  	                    }
 	                    
                     }
                 }
                 System.out.println("수강신청 및 subject_schedule_db에 추가 완료!");
                 return "수강신청 완료!";
            }

            System.out.println("토큰이 유효하지 않습니다.");
            return "토큰이 유효하지 않습니다.";
        }

        System.out.println("토큰이 없습니다.");
        return "토큰이 없습니다.";
    }
    
   // cart.jsp(수강희망/관심과목 등록 페이지)
   @RequestMapping("/sugang/cart")
    public String cart(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                Model model ) {

       return "/sugang/cart";
    }

   //cart.jsp - 조회 버튼 해당되는 리스트 출력
   @PostMapping("/sugang/cart")
   @ResponseBody
   public ResponseEntity subject(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                                    @RequestBody Map<String, String> requestBody,                             
                                      String Order,
                                      Model model ) {
      String grade = requestBody.get("grade");
      String subject_Type = requestBody.get("subject_Type");
      String department_Name = requestBody.get("department_Name");
      String subject_Point = requestBody.get("subject_Point");
      String day = requestBody.get("day");
      String start_Time_Output = requestBody.get("start_Time_Output");
      String end_Time_Output = requestBody.get("end_Time_Output");
      String professor_Name = requestBody.get("professor_Name");
      String subject_No = requestBody.get("subject_No");
      String subject_Name = requestBody.get("subject_Name");
       System.out.println("토큰"+token);
      if (token != null && token.startsWith("BEARER ")) {
           
            String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
            // 여기서 jwtToken을 검증하고 필요한 작업 수행
            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            if (check) {

               List<Subject_DTO> subjects = service.subject(grade, subject_Type,department_Name, subject_Point, day,
                                           start_Time_Output, end_Time_Output,
                                           professor_Name, subject_No, subject_Name, Order, model);

               return new ResponseEntity<>(subjects, HttpStatus.OK);
            }
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
      }
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");

    }
   
 //cart.jsp - 리스트에서 과목코드 내 강의 계획안
   @RequestMapping("/sugang/detail")
   public String detail(Subject_DTO subject,Model model, int subject_No) {
      
      subject = service.getSubject(subject_No);
      model.addAttribute("subject", subject);
      return "/sugang/detail";
   }
   
   //cart.jsp - 나타난 리스트에서 (시작) 정렬버튼
   @PostMapping("/sugang/order")
	@ResponseBody
	public ResponseEntity order(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
								@RequestBody Map<String, String> requestBody, Model model ) {
		String grade = requestBody.get("grade");
		String subject_Type = requestBody.get("subject_Type");
		String department_Name = requestBody.get("department_Name");
		String subject_Point = requestBody.get("subject_Point");
		String day = requestBody.get("day");
		String start_Time_Output = requestBody.get("start_Time_Output");
		String end_Time_Output = requestBody.get("end_Time_Output");
		String professor_Name = requestBody.get("professor_Name");
		String subject_No = requestBody.get("subject_No");
		String subject_Name = requestBody.get("subject_Name");
		String Order = requestBody.get("Order");
		System.out.println("토큰"+token);
		if (token != null && token.startsWith("BEARER ")) {
       	
           String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
           // 여기서 jwtToken을 검증하고 필요한 작업 수행
           boolean check = JwtTokenProvider.isValidToken(jwtToken);
           if (check) {
				System.out.println(Order);
				System.out.println(professor_Name);
				List<Subject_DTO> subjects = service.subject(grade, subject_Type,department_Name, subject_Point, day,
															start_Time_Output, end_Time_Output,
															professor_Name, subject_No, subject_Name, Order, model);
				
		
				return new ResponseEntity<>(subjects, HttpStatus.OK);
           }
       	return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
		}
   	return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");

   }
   
 //cart.jsp - 수강희망/관심과목 내역(신청 버튼)
   @ResponseBody
   @PostMapping(value = "/sugang/save-data-endpoint", produces = "application/json; charset=utf-8")
   public String saveData(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                          @RequestBody Map<String, Object> requestBody, Model model) {

       System.out.println("토큰" + token);
       if (token != null && token.startsWith("BEARER ")) {

           String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
           // 여기서 jwtToken을 검증하고 필요한 작업 수행
           boolean check = JwtTokenProvider.isValidToken(jwtToken);
           if (check) {

               String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
               int student_No = Integer.parseInt(student_no);
               String name = JwtTokenProvider.parseTokenToName(jwtToken);          //name 추출

               // 여러 개의 subject_No가 들어올 수 있으므로 List<Integer>로 받기
               List<Integer> subjectNos = (List<Integer>) requestBody.get("subject_No");

               for (Integer subject_No : subjectNos) {
                   Cart_DTO cartDTO = new Cart_DTO();
                   cartDTO.setSubject_No(subject_No);
                   cartDTO.setStudent_No(student_No);

                   Integer checkS = mapper.checkCartData(subject_No, student_No);
                   if (checkS == 0) { // 기존에 카트에 담겨있지 않으면
                	   
                      Subject_DTO subjects = mapper.getSubject(subject_No);
                      String result = service.saveCart(student_no, name, subjects);
                	  int res;
                	  
                      if(result.equals("같은 시간에 이미 수업이 있습니다.")) {
                    	  System.out.println(subject_No + "번은 같은 시간에 이미 수업이 있습니다.");
                    	  return subject_No + "번은 같은 시간에 이미 수업이 있습니다.";
                      } else if(result.equals("신청 완료")) {
                    	  res = mapper.insertData(cartDTO); // 카트에 담기
                          System.out.println(subject_No + "번 신청 완료");
                      } else {
                    	  System.out.println("신청 실패");
                    	  return "신청 실패";
                      }
                      
                       if (res > 0) {
                           System.out.println("과목 번호 " + subject_No + "번이 장바구니에 담겼습니다.");
                       } else {
                           System.out.println("과목 번호 " + subject_No + "번 장바구니 등록 실패");
                       }
                   } else {
                       System.out.println("이미 신청한 과목입니다. (과목 번호: " + subject_No + ")");
                       return subject_No + "번은 같은 시간에 이미 수업이 있습니다.";
                   }
               }
               System.out.println("장바구니 등록 완료!");
               return "장바구니 등록 완료!";
           }
           System.out.println("토큰이 유효하지 않습니다.");
           return "토큰이 유효하지 않습니다.";
       }

       System.out.println("토큰이 없습니다.");
       return "토큰이 없습니다.";
       

   }
    
   //cart.jsp - 수강신청 내역 (1)리스트
   @PostMapping("/sugang/cart_show")
   @ResponseBody
   public ResponseEntity<List<Cart_DTO>> showCart(
           @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
           @RequestBody Map<String, String> requestBody) {

      String subject_No = requestBody.get("subject_No");

       System.out.println("토큰" + token);
       System.out.println("request_subject_No : " + subject_No);

       if (token != null && token.startsWith("BEARER ")) {
           String jwtToken = token.substring(7);

           boolean check = JwtTokenProvider.isValidToken(jwtToken);
           if (check) {
               String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
               List<Cart_DTO> carts = service.showCart(subject_No, student_no);
               System.out.println("request_subject_No : " + subject_No);
               return new ResponseEntity<>(carts, HttpStatus.OK);
           }

           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
       }

       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
   }
   
   //cart.jsp - 수강신청 내역 (2) 취소버튼
   @PostMapping("/sugang/cart_show_delete")
   @ResponseBody
   public ResponseEntity<List<Cart_DTO>> cartShowdelete(
           @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
           @RequestBody Map<String, Integer> requestBody) {

      Integer subject_No = requestBody.get("subject_No");

       System.out.println("토큰" + token);
       System.out.println("delete subject_No : " + subject_No);

       if (token != null && token.startsWith("BEARER ")) {
           String jwtToken = token.substring(7);

           boolean check = JwtTokenProvider.isValidToken(jwtToken);
           if (check) {
               String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
               service.cartShowdelete(subject_No, student_no); // 삭제하는 부분 

               return new ResponseEntity<>(HttpStatus.OK);
           }

           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
       }
       
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
   }
   
   //cart.jsp - 수강신청 내역 (3) 전체 삭제
   @ResponseBody
   @PostMapping(value = "/sugang/cart_deleteAll", produces = "application/json; charset=utf-8")
   public String cart_deleteAll(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                                Model model) {
       System.out.println("토큰" + token);
       if (token != null && token.startsWith("BEARER ")) {
           String jwtToken = token.substring(7);
           boolean check = JwtTokenProvider.isValidToken(jwtToken);

           if (check) {
               String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken);
               String Student_Name = JwtTokenProvider.parseTokenToName(jwtToken);   //name 추출
               int student_No = Integer.parseInt(student_no);

               // student_No를 이용하여 해당 사용자의 모든 수강 내역 삭제
               int res = service.cart_deleteAll(student_No);

               if (res > 0) {
                   System.out.println("사용자 " + student_No + "의 모든 수강 내역이 삭제되었습니다.");
               } else {
                   System.out.println("사용자 " + student_No + "의 모든 수강 내역 삭제 실패");
               }

               System.out.println("모든 수강 내역이 삭제되었습니다!");
               return "모든 수강 내역이 삭제되었습니다!";
           }

           System.out.println("토큰이 유효하지 않습니다.");
           return "토큰이 유효하지 않습니다.";
       }

       System.out.println("토큰이 없습니다.");
       return "토큰이 없습니다.";
   }

 
 
   
 

 //옆 sideBar - 수강신청 안내
   @RequestMapping("/sugang/info")
   public String info(Model model) {
      return "/sugang/info";
   }

   //옆 sideBar - 시간표
   @GetMapping("/sugang/timeTable")
   public String timeTable() {
      return "/sugang/timeTable";
   }
   
   // 시간표 설정
   @PostMapping("/sugang/timeTable")
   public ResponseEntity timeTable(Model model, @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token
                  ) {
       // JSON 형식의 응답 객체 생성
       Map<String, Object> response = new HashMap<>();

      System.out.println("시간표토큰"+token);
      if (token != null && token.startsWith("BEARER ")) {
           
            String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
            // 여기서 jwtToken을 검증하고 필요한 작업 수행
            boolean check = JwtTokenProvider.isValidToken(jwtToken);
            if (check) {
               String student_no = JwtTokenProvider.getUserIdFromToken(jwtToken); 
                String name = JwtTokenProvider.parseTokenToName(jwtToken); 
              System.out.println("이름:"+name+" , 학번 : "+student_no);
            // 스케줄
            int Student_No = Integer.parseInt(student_no);
            List<Subject_DTO> student_Schedule = new ArrayList<Subject_DTO>();      
            student_Schedule = service.get_Student_Schedule(Student_No, model);
               
            // table_Count 생성
            for (int i = 0; i < student_Schedule.size(); i++) {
               Subject_DTO dto = student_Schedule.get(i);
               dto.setTable_Count(dto.getStudy_Time()/30);
               
            }      
      
            // 컬러
               String [] time_Table_Color = {"#FFB4B4", "#FAECC5", "#E4F7BA", "#CEFBC9", "#D4F4FA", "#E8D9FF", "#FFD9EC", "#FFC19E",
                     "#FFF29E", "#CEF279", "#B7F0B1", "#B2EBF4", "#B2CCFF", };
                     
               // # java script 배열 사용, json 배열로 변환하기 위한 ObjectMapper 선언
               ObjectMapper objectMapper = new ObjectMapper();
                  try {

                      String time_Table_Color_Json = objectMapper.writeValueAsString(time_Table_Color);
                      
                      System.out.println(time_Table_Color);
                      String student_Schedule_Json = objectMapper.writeValueAsString(student_Schedule);
                      System.out.println(student_Schedule);       
                      
                      response.put("student_Schedule", student_Schedule);
                      response.put("time_Table_Color", time_Table_Color);
                      
                  }catch (Exception e) {
                     System.out.println("json 변환 실패");
                  }
               
            
         // 요일         
            String [] time_Table_Day = {"월요일", "화요일", "수요일", "목요일", "금요일"};   

         // 시간
            double [] time_Table_Time = service.get_Class_Time_Code();


                  response.put("time_Table_Day", time_Table_Day);
                  response.put("time_Table_Time", time_Table_Time);

           return new ResponseEntity<>(response, HttpStatus.OK);
        }
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
   }
   return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");

}
   
 //수강신청 페이지 오픈 시간설정
   @GetMapping("/sugang/timeSet")
   public String timeSet() {
      return "/sugang/sugangTimeSet";
   }
   
   @PostMapping("/sugang/timeSet")
   @ResponseBody
   public ResponseEntity subject(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
                        @RequestBody Map<String, String> requestBody ) {
      String yearSelect = requestBody.get("yearSelect");
      String monthSelect = requestBody.get("monthSelect");
      String daySelect = requestBody.get("daySelect");
      String hourSelect = requestBody.get("hourSelect");
      String minSelect = requestBody.get("minSelect");
      String endYearSelect = requestBody.get("endYearSelect");
      String endMonthSelect = requestBody.get("endMonthSelect");
      String endDaySelect = requestBody.get("endDaySelect");
      String endHourSelect = requestBody.get("endHourSelect");
      String endMinSelect = requestBody.get("endMinSelect");
      
      LocalDateTime timeSet = LocalDateTime.of(
                  Integer.parseInt(yearSelect),
                  Integer.parseInt(monthSelect),
                  Integer.parseInt(daySelect),
                  Integer.parseInt(hourSelect),
                  Integer.parseInt(minSelect)
      );
      LocalDateTime endTimeSet = LocalDateTime.of(
            Integer.parseInt(endYearSelect),
            Integer.parseInt(endMonthSelect),
            Integer.parseInt(endDaySelect),
            Integer.parseInt(endHourSelect),
            Integer.parseInt(endMinSelect)
            );

      // DateTimeFormatter를 사용하여 원하는 형식으로 포맷팅
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
      targetDateTime = timeSet.format(formatter);
      endTargetDateTime = endTimeSet.format(formatter);
              
       System.out.println("토큰"+token);
         if (token != null && token.startsWith("BEARER ")) {
              
               String jwtToken = token.substring(7); // "Bearer " 이후의 부분이 토큰
               
               // 여기서 jwtToken을 검증하고 필요한 작업 수행
               boolean check = JwtTokenProvider.isValidToken(jwtToken);
               
               if (check) {
            	  String name = JwtTokenProvider.getUserIdFromToken(jwtToken);
            	  if(name.equals("admin"))
            		  return new ResponseEntity<>("시간 설정 완료", HttpStatus.OK);
            	  return new ResponseEntity<>("설정 권한이 없습니다.", HttpStatus.OK);
               }
              return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
         }
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");

       }

		//장바구니 페이지 닫는 시간 설정
		@PostMapping("/sugang/getTime")
		@ResponseBody
		public ResponseEntity getData() {
		   Map<String, String> response = new HashMap<>();
		    // targetDateTime가 null인 경우 10일 뒤 날짜를 기본 값으로 설정
		    if (targetDateTime == null) {
		        targetDateTime = LocalDateTime.now().plusDays(10).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
		    }
		
		    // endTargetDateTime이 null인 경우 11일 뒤 날짜를 기본 값으로 설정
		    if (endTargetDateTime == null) {
		        endTargetDateTime = LocalDateTime.now().plusDays(11).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
		    }
		   response.put("targetDateTime", targetDateTime);
		   response.put("endTargetDateTime", endTargetDateTime);
		    return ResponseEntity.ok(response);
		}

}