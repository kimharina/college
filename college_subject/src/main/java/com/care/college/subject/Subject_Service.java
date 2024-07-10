package com.care.college.subject;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;


@Service
public class Subject_Service {
   @Autowired
   private Subject_Mapper mapper;

   //로그인 체크
   public String loginProc(String student_no, String password, Model model, String No, String Name, String Pw) {
               
      if (student_no == null || student_no.trim().isEmpty()) {
         return "학번을 입력하세요.";
      }
      if (password == null || password.trim().isEmpty()) {
         return "비밀번호를 입력하세요.";
      }
      
      int no = Integer.parseInt(student_no);
      
      //관리자가 로그인할 경우(학번0)
      if (student_no.trim().equals("0")) {
         No = mapper.getNo(no);
         Name = mapper.getName(no);
         Pw = mapper.getPw(no);
         if (Name != null && password.equals("admin1234") == true) {   
            return "관리자입니다.";
         }
      }
      //비번이 7자리면 비밀번호 변경 아니면 로그인성공
      No = mapper.getNo(no);
      Name = mapper.getName(no);
      Pw = mapper.getPw(no);
      if (password.length() == 7) {
         if (Name != null && password.equals(Pw)) {            
            model.addAttribute("Name", Name);
            return "비밀번호를 변경해주세요.";
         }
         return "학번 또는 비밀번호를 확인 후 다시 입력하세요.";
      } else {
         BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
         if (Name != null && encoder.matches(password, Pw) == true) {
            model.addAttribute("Name", Name);
            model.addAttribute("No", No);

            return "로그인 성공";
         }
      return "학번 또는 비밀번호를 확인 후 다시 입력하세요.";
      }
   }

 //sugang.jsp - 과목코드로 신청(검색)
   public List<Subject_DTO> searchCart(String search, String select, String student_no) {
      List<Subject_DTO> subjects = mapper.searchCart(search,select);      //검색한 조건에 맞는 검색 결과값

      return subjects;
   }
   
 //sugang.jsp - 과목코드로 신청(신청 버튼)
   public String saveSugang(String student_no, String name, Subject_DTO subjects) {
      int student_No = Integer.parseInt(student_no);
      
      //겹치는 시간표 있으면 신청 실패
      String day = subjects.getDay();            //신청한 수업 요일
      double sTime = subjects.getStart_Time();   //신청한 수업 시작 시간
      double eTime = subjects.getEnd_Time();      //신청한 수업 끝나는 시간
      
      Subject_DTO[] schedules = mapper.getSchedule(student_No, day);

      for (Subject_DTO schedule : schedules) {
         if(schedule.getStart_Time() <= sTime && schedule.getEnd_Time() > sTime ||
            schedule.getStart_Time() < eTime && schedule.getEnd_Time() >= eTime ) {
            return "같은 시간에 이미 수업이 있습니다.";   
         }
      }
      
      if(subjects.getStudent_Count() > subjects.getStudent_Count_ing()) {
         subjects.setStudent_Count_ing( subjects.getStudent_Count_ing() + 1 ) ;
         System.out.println("현재수강인원 : "+ subjects.getStudent_Count_ing());
         
         int result = mapper.saveSchedule(student_No, name, subjects);
         if(result == 0) {
            return "신청 실패";
         } else {
            mapper.studentPlus(subjects.getSubject_No());      // 현재수강인원 플러스하기
            return "신청 완료";
         }
      } else {
         return "인원이 초과되었습니다.";
      }
      
   }
   
   
  //	"/request" - sugang.jsp - 관심과목으로 신청(리스트 나타내기)
   public List<Cart_DTO> requestCart(String subject_No, String student_No) {
	   int student_no = Integer.parseInt(student_No);
       List<Cart_DTO> carts = mapper.requestCart(subject_No, student_no);
       return carts;
   }
   
  //	"/delete-endpoint" - sugang.jsp - 관심과목으로 신청(취소 버튼)
   public int deleteCart(Integer subject_No, String student_no) {
          return mapper.deleteCart(subject_No);
      }
   
  //	"/request_final" - cart_DTO에 있는 데이터를 가져오는 작업 추가
   public List<Cart_DTO> getCartData(Integer subject_No, int student_No, String Student_Name) {
	    return mapper.getCartData(subject_No, student_No, Student_Name);
	}
   
    //	"/request_final" - subject_schedule_db에 데이터 추가
	public String addToSubjectSchedule(List<Cart_DTO> cartList, Subject_DTO subjects, int student_No, String student_Name) {
		//겹치는 시간표 있으면 신청 실패
	      String day = subjects.getDay();            //신청한 수업 요일
	      double sTime = subjects.getStart_Time();   //신청한 수업 시작 시간
	      double eTime = subjects.getEnd_Time();      //신청한 수업 끝나는 시간
	      
	      Subject_DTO[] schedules = mapper.getSchedule(student_No, day);
	      
	      for (Subject_DTO schedule : schedules) {
	    	  if(schedule.getStart_Time() <= sTime && schedule.getEnd_Time() > sTime ||
	    			schedule.getStart_Time() < eTime && schedule.getEnd_Time() >= eTime ) {
	    		  	return "겹치는 시간이 있습니다.";  
		      }
		   }
		
	      if(subjects.getStudent_Count() > subjects.getStudent_Count_ing()) {
	          subjects.setStudent_Count_ing( subjects.getStudent_Count_ing() + 1 ) ;
	          System.out.println("현재수강인원 : "+ subjects.getStudent_Count_ing());
	           
	          int result = mapper.saveSchedule(student_No, student_Name, subjects);
	          System.out.println(result);
	          return "신청 완료!";
	       } else {
	          return "인원이 마감되었습니다.";
	       }

	}

	//	"/request_final" - cart_DTO에 있는 데이터 중복 확인을 위한 작업
	public List<Integer> getExistingSubjects(int student_No) {
		return mapper.getExistingSubjects(student_No);
	}
	

	//cart.jsp
	   public void cart(Model model) {
		      

	       List<Subject_DTO> subjects = mapper.cart();
	       
	       model.addAttribute("subjects", subjects);

	   }
	   
	 //cart.jsp - 조회 버튼 해당되는 리스트 출력
	   public List<Subject_DTO> subject(String grade, String subject_Type, String department_Name, String subject_Point, String day, String start_Time_Output, String end_Time_Output, String professor_Name, String subject_No, String subject_Name, String Order, Model model) {
	      Double sTime = mapper.Start_Time(start_Time_Output);
	      Double eTime = mapper.End_Time(end_Time_Output);
	         List<Subject_DTO> subjects = mapper.searchSubject(grade, subject_Type, department_Name, subject_Point, day, sTime, eTime, professor_Name, subject_No, subject_Name, Order);

	       //model.addAttribute("subjects", subjects);
	       return subjects;
	   }
	   
	 //cart.jsp - 카트담기
	   public String saveCart(String student_no, String name, Subject_DTO subjects) {
		   int student_No = Integer.parseInt(student_no);
		   
		   //겹치는 시간표 있으면 신청 실패
		   String day = subjects.getDay();            //신청한 수업 요일
		   double sTime = subjects.getStart_Time();   //신청한 수업 시작 시간
		   double eTime = subjects.getEnd_Time();      //신청한 수업 끝나는 시간
		   
		   Subject_DTO[] schedules = mapper.getCartSub(student_No, day);
		   
		   for (Subject_DTO schedule : schedules) {
			   if(schedule.getStart_Time() <= sTime && schedule.getEnd_Time() > sTime ||
					   schedule.getStart_Time() < eTime && schedule.getEnd_Time() >= eTime ) {
				   return "같은 시간에 이미 수업이 있습니다.";   
			   }
		   }
		  return "신청 완료"; 
	   }

	   //cart.jsp - 리스트에서 과목코드 내 강의 계획안
	   public Subject_DTO getSubject(int subject_No) {
	      Subject_DTO subject = mapper.getSubject(subject_No);

	      return subject;
	   }
	   
	   //cart.jsp - 수강신청 내역
	   public List<Cart_DTO> showCart(String subject_No, String student_no) {
		   int student_No = Integer.parseInt(student_no);
	       List<Cart_DTO> carts = mapper.showCart(subject_No, student_No);
		    return carts;
		} 
	   
	   //cart.jsp - 수강신청 내역 (2) 취소버튼 "/cart_show_delete"
	   public int cartShowdelete(Integer subject_No, String student_no) {
		   
	          return mapper.cartShowdelete(subject_No);
	   }
	   
	   //cart.jsp - 수강신청 내역 (3) 전체 삭제 "/cart_deleteAll"
		public int cart_deleteAll(int student_No) {
			return mapper.cart_deleteAll(student_No);
		}
		
    // 시간표 설정 - 스케줄
   public List<Subject_DTO> get_Student_Schedule(int student_No, Model model) {       
      List<Subject_DTO> Student_Schedule = mapper.get_Subject_Schedule(student_No);
      return Student_Schedule;
   }
   
   // 시간표 설정 - 시간
   public double[] get_Class_Time_Code() {
     double [] time_Table_Time = mapper.get_Class_Time_Code();
     return time_Table_Time;
  }

   




}