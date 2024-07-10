package com.care.college.subject;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface Subject_Mapper {
	//로그인 체크 - 관리자가 로그인할 경우(no)
   String getNo(int no);
   
  //로그인 체크 - 관리자가 로그인할 경우(name)	  
   String getName(int no);

   //로그인 체크 - 관리자가 로그인할 경우(pw)
   String getPw(int no);  
 
  //sugang.jsp - 과목코드로 신청(검색)
   List<Subject_DTO> searchCart(String search, String select);
   
   //sugang.jsp - 과목코드로 신청(신청 버튼), 겹치는 시간표확인
   Subject_DTO[] getSchedule(int student_No, String day);
   
   //cart.jsp - 겹치는 카트과목확인
   Subject_DTO[] getCartSub(int student_No, String day);
   
  //sugang.jsp - 과목코드로 신청(신청 버튼), 결과
   int saveSchedule(int student_No, String name, Subject_DTO subjects);

  //sugang.jsp - 과목코드로 신청(신청 버튼), 현재수강인원 플러스
   void studentPlus(int subject_No);
   
   //	"/request" - sugang.jsp - 관심과목으로 신청(리스트 나타내기)
   List<Cart_DTO> requestCart(String subject_No, int student_no);
   
   //	"/delete-endpoint" - sugang.jsp - 관심과목으로 신청(취소 버튼)
   int deleteCart(Integer subject_No);

   //	"/request_final" - cart_DTO에 있는 데이터를 가져오는 작업 추가
   List<Cart_DTO> getCartData(Integer subject_No, int student_No, String Student_Name);
   
   //	"/request_final" - subject_schedule_db에 데이터 추가
   int addToSubjectSchedule(List<Cart_DTO> cartList);

   //	"/request_final" - cart_DTO에 있는 데이터 중복 확인을 위한 작업
   List<Integer> getExistingSubjects(int student_No);

   // 시간표 설정 - 시간
   double[] get_Class_Time_Code();

   // 시간표 설정 - 스케줄
   List<Subject_DTO> get_Subject_Schedule(int student_No);

   //cart.jsp
   List<Cart_DTO> cartList(int student_No);
   
   //cart.jsp
   List<Subject_DTO> cart();
   
   //cart.jsp - 조회 버튼 해당되는 리스트 출력
   List<Subject_DTO> searchSubject(@Param("grade") String grade,
                     @Param("subject_Type") String subject_Type, 
                     @Param("department_Name") String department_Name, 
                     @Param("subject_Point") String subject_Point, 
                     @Param("day") String day, 
                     @Param("sTime") Double sTime, 
                     @Param("eTime") Double eTime, 
                     @Param("professor_Name") String professor_Name, 
                     @Param("subject_No") String subject_No, 
                     @Param("subject_Name") String subject_Name, String Order);

   //cart.jsp - 조회 버튼 해당되는 리스트 출력(시작시간)
   Double Start_Time(String start_Time_Output);

   //cart.jsp - 조회 버튼 해당되는 리스트 출력(종료시간)
   Double End_Time(String end_Time_Output);

  //cart.jsp - 리스트에서 과목코드 내 강의 계획안
   Subject_DTO getSubject(int subject_No);
   
   //cart.jsp - 수강희망/관심과목 내역(신청 버튼), 카트에 담기
   int insertData(Cart_DTO cartDTO);
   
   //cart.jsp - 수강희망/관심과목 내역(신청 버튼), 기존에 카트에 담겨 있는지
   Integer checkCartData(Integer subjectNo, int student_No);

   //cart.jsp - 수강신청 내역 (1) 리스트
   List<Cart_DTO> showCart(String subject_No, int student_No);

   //cart.jsp - 수강신청 내역 (2) 취소버튼 "/cart_show_delete"
   int cartShowdelete(Integer subject_No);

   //cart.jsp - 수강신청 내역 (3) 전체 삭제 "/cart_deleteAll"
   int cart_deleteAll(int student_No);

}