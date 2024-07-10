package com.care.college.admin;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import com.care.college.admin.department.DepartmentDTO;
import com.care.college.admin.department.IDepartmentMapper;
import com.care.college.admin.professor.ProfessorDTO;
import com.care.college.admin.professor.IProfessorMapper;
import com.care.college.admin.student.IStudentMapper;
import com.care.college.admin.student.StudentDTO;
import com.care.college.admin.subject.Class_time_dbDTO;
import com.care.college.admin.subject.IClassTimeMapper;
import com.care.college.admin.subject.ISubjectMapper;
import com.care.college.admin.subject.SubjectDTO;

@Service
public class AdminService {
	@Autowired private IDepartmentMapper departDAO;	//학과 mapper
	@Autowired private IProfessorMapper proDAO;  //교수 mapper
	@Autowired private IStudentMapper stuDAO;	//학생 mapper
	@Autowired private IClassTimeMapper classDAO; // class_Time mapper
	@Autowired private ISubjectMapper subDAO;
	
	//관리자의 학과관리 부분 시작
	public String department_regist_proc(DepartmentDTO departmentDTO) {
			
		int rs = departDAO.depart_regist(departmentDTO);
		
		String result = "등록 실패";
		if(rs != 0) {
			result = "등록 성공";
		}
		return result;
		
	}

	public void department_list(Model model) {
		
		ArrayList<DepartmentDTO> departments = departDAO.depart_list();
		
		model.addAttribute("departments", departments);
	}

	//학과 정보입니다
	public void department_info(String department_Name, Model model) {
		DepartmentDTO department = departDAO.depart_info(department_Name);
		
		model.addAttribute("department", department);
	}
	
	//학과의 세부정보입니다.
	public void department_detail_info(String department_Name, Model model) {
		DepartmentDTO department = departDAO.depart_info(department_Name); // 학과의 코드번호, 학생 수를 가져옴
		ArrayList<String> professors = proDAO.depart_pro_list(department_Name); // 학과에 속해있는 교수님들을 가져옴

		model.addAttribute("department", department);
		model.addAttribute("professors", professors);
	}

	public void department_update_proc(Model model, String department_New_Name, int department_No) {
		int rs = departDAO.depart_update(department_No, department_New_Name);
		
		String result = "수정 실패";

		if (rs != 0) {
			result = "수정 성공";
		}
		
		model.addAttribute("result", result);
	}

	public void department_delete(String department_Name, Model model) {
		int rs = departDAO.depart_delete(department_Name);

		String result = "삭제 실패";
		if (rs != 0) {
			result = "삭제 성공";
		}
		
		model.addAttribute("result", result);
	}
	//관리자의 학과관리 부분 끝

	
	//관리자의 교수관리 부분 시작
	public String professor_regist_proc(ProfessorDTO professorDTO) {
		int rs = proDAO.pro_regist(professorDTO);

		String result = "등록 실패";
		if(rs != 0) {
			result = "등록 성공";
		}
		return result;
	}

	public void professor_list(Model model) {
		ArrayList<ProfessorDTO> professors = proDAO.pro_list();
		
		model.addAttribute("professors", professors);
	}

	public void professor_info(Model model, int professor_No) {
		ProfessorDTO professor = proDAO.pro_info(professor_No);
		
		model.addAttribute("professor", professor);
	}

	public void professor_update_proc(String department_New_Name, String professor_New_Name, int professor_No, Model model) {
		int rs = proDAO.pro_update(professor_No, department_New_Name, professor_New_Name);
		
		String result = "수정 실패";

		if (rs != 0) {
			result = "수정 성공";
		}
		
		model.addAttribute("result", result);
		
	}

	public void professor_delete(int professor_No, Model model) {
		int rs = proDAO.pro_delete(professor_No);

		String result = "삭제 실패";
		if (rs != 0) {
			result = "삭제 성공";
		}
		
		model.addAttribute("result", result);
		
	}
	//관리자의 교수관리 부분 끝

	
	//관리자의 학생관리 부분 시작
	//학생 등록(관리자는 학생의 인적사항들을 갖고있으니 학생의 인적사항을 보고 학생을 등록시켜줌)
	public String student_regist_proc(StudentDTO studentDTO, int years) {
		
		DepartmentDTO depart = departDAO.depart_info(studentDTO.getDepartment_Name());	//학과에 등록하기 위해 해당 학과의 정보들을 가져옴.
		
		//학번(student_No)을 만들기위한 작업 시작. 7자리이며 숫자를 문자열로 바꾸어서 붙여주고 최종적으로는 문자열을 숫자로 바꾸어서 값을 넘겨줄 예정임.
		int depart_code = depart.getDepartment_No();	//학과의 코드를 구해옴 - int
		String d_code = "";	//학과의 코드를 문자열로 변환해서 담아둘 변수 - String
		
		if(depart_code < 10) {		//학과의 코드가 10보다 작으면 앞에 문자열 0을 넣어서 2자리의 문자열로 바꾸어주고
			d_code = "0" + depart_code;
		}else {
			d_code = Integer.toString(depart_code);
		}
		
		int depart_student_code = (depart.getStudent_Count() + 1);	//학과의 현재 학생 수 + 1을 해주었고 - int
		String d_s_code = "";	//학과의 현재 학생수를 문자열로 변환해서 담아둘 변수 - String
		
		if(depart_student_code < 10) {	//학과의 학생수가 10보다 작으면 앞에 문자열 00을 넣어서 3자리의 문자열로 바꾸어주고
			d_s_code = "00" + Integer.toString(depart_student_code);
		}else if(depart_student_code < 100){	//학과의 학생수가 100보다 작으면 앞에 문자열 0을 넣어서 3자리의 문자열로 바꾸어주고
			d_s_code = "0" + Integer.toString(depart_student_code);
		}else {
			d_s_code = Integer.toString(depart_student_code);
		}
		
		int grade = 0;
		if (studentDTO.getGrade().equals("1학년")) {
			grade = 1;
		}else if(studentDTO.getGrade().equals("2학년")) {
			grade = 2;
		}else if(studentDTO.getGrade().equals("3학년")) {
			grade = 3;
		}else {
			grade = 4;
		}
		
		String post_code = Integer.toString( years + 1 - grade );
		//입학년도에 맞는 학년 코드 ex) 23년도에 1학년으로 입학하면 23학번이 되고, 23년도에 2학년으로 편입하면 22학번이 되도록 설정
		
		int stu_code = Integer.parseInt(post_code + d_code + d_s_code);	//post_code, d_code, d_s_code 3개를 전부 이어서 붙여준 뒤 정수형으로 변경 후 넘겨줌
		
		departDAO.student_count_plus(studentDTO.getDepartment_Name());	//DB에 저장된 학생수를 + 1 해서 변경사항을 적용시킴
		
		
		studentDTO.setStudent_No(stu_code);
		
		//학생 초기 비밀번호 암호화 설정 
		//BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		//String password = encoder.encode(pw);
		
		//studentDTO.setPassword(pw);
		
		
		int rs = stuDAO.stu_regist(studentDTO);
		
		String result = "등록 실패";
		if(rs != 0) {
			result = "등록 성공";
		}
		return result;
	}
	
	//학생들의 목록
	public void student_list(Model model) {
		ArrayList<StudentDTO> students = stuDAO.stu_list();
		
		model.addAttribute("students", students);
	}

	//학생 정보
	public void student_info(int student_No, Model model) {
		StudentDTO student = stuDAO.stu_info(student_No);
		
		model.addAttribute("student", student);
	}

	//학생 정보 수정
	public void student_update_proc(String student_num, String name, String department_Name, String grade,
			String tel, String email, String birthday, String address, String pw, StudentDTO studentDTO, Model model) {
			
					
			int student_num_int = Integer.parseInt(student_num);
			studentDTO.setStudent_No(student_num_int);
			
//			BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
//			String password = encoder.encode(pw);
			studentDTO.setPassword(pw);
			
			studentDTO.setName(name);
			studentDTO.setDepartment_Name(department_Name);
			studentDTO.setTel(tel);
			studentDTO.setEmail(email);
			studentDTO.setBirth(birthday);
			studentDTO.setAddress(address);
			
			int rs = stuDAO.stu_update(studentDTO);
			
			String result = "수정 실패";

			if (rs != 0) {
				result = "수정 성공";
			}
			
			model.addAttribute("result", result);
		}

	//학생 삭제
	public void student_delete(int student_No, Model model) {
		
		//학생이 사라지면 학과의 학생 수를 -1 해줌
		StudentDTO student = stuDAO.stu_info(student_No);	//학생의 정보를 가져와서
		
		departDAO.student_count_minus(student.getDepartment_Name());	//학과명을 전달해서 학과의 인원 -1 해줌
		
		
		int rs = stuDAO.stu_delete(student_No);
		
		String result = "삭제 실패";
		if (rs != 0) {
			result = "삭제 성공";
		}
		
		model.addAttribute("result", result);
		
	}
	//관리자의 학생 관리 부분 끝

	
	//관리자의 강좌 관리 부분 시작
	//강좌를 등록하기 전에 시간들을 가져오는 부분
	public List<Class_time_dbDTO> get_Class_Time() {
		
		return classDAO.get_Class_Time();
	}
	
	//강좌 등록 - 교수님의 이름이 중복될 수 있어서 학과까지 따로 선택받아서 가져왔습니다.
	public String subject_regist_proc(String department_Name, String subject_Name, String pro_department,
			String professor_Name, String day, String grade, String start_Time, String end_Time, String subject_Type,
			String subject_Point, int student_Count, SubjectDTO subjectDTO, Model model) {

		//department_No + day + (end_Time - start_Time) + (서브젝트_카운트 + 1값)
		//강좌의 코드는 -- 학과(1 ~ 2) + 요일(1) + 시간(1) + 해당학과의 과목수(2) - 최소 5글자, 최대 6글자로 구성했습니다.
		DepartmentDTO depart = departDAO.depart_info(department_Name);
		
		String d_code = "";				//학과의 코드를 찾아서
		depart.getDepartment_No();
		if(depart.getDepartment_No() < 10) {		//학과의 코드가 1자리수라면 앞에 문자열 0을 더해서 문자열 6자리를 맞추었습니다.
			d_code = "0" + Integer.toString(depart.getDepartment_No());
		}else {
			d_code = Integer.toString(depart.getDepartment_No());
		}
		
		String day_code = "";	//요일별로 1~5값을 넣어주기위한 부분입니다.
		if(day.equals("월요일")) {
			day_code = "1";
		}else if(day.equals("화요일")) {
			day_code = "2";
		}else if(day.equals("수요일")) {
			day_code = "3";
		}else if(day.equals("목요일")) {
			day_code = "4";
		}else {
			day_code = "5";
		}
		
		//jsp에서 {(종료시간 - 시작시간) < 0.5} 조건을 걸어두었고 문자열로 받아와서 수업시간을 시간코드로 변환하는 부분입니다.
		int study_Time = (int) ((Double.parseDouble(end_Time) - Double.parseDouble(start_Time)));
		String time_code = Integer.toString(study_Time);
		
		//해당학과의 정보를 가져와서 해당 학과에 포함된 과목들의 숫자 +1을 한 후 과목코드로 변환하는 부분입니다.
		int subject_cnt = depart.getSubject_Count() + 1;
		String subject_cnt_code;
		if(subject_cnt < 10) {
			subject_cnt_code = "0" + subject_cnt;
		}else {
			subject_cnt_code = Integer.toString(subject_cnt);
		}
		
		
		//강좌 코드를 만들어서 문자열 -> 숫자로 parsing. 그 후 직접 강좌DTO에 set해주었습니다.
		
		String subject_No_code = d_code + day_code + time_code + subject_cnt_code;
		int subject_No = Integer.parseInt(subject_No_code);
		
		
		//시간출력(String)용 컬럼이 있어서 과목DTO에 약간의 수정과 class_time DB에서 조회해서 들고오는 방법으로 사용했습니다.
		String start_Time_Output = classDAO.trans_class_time(Double.parseDouble(start_Time));
		String end_Time_Output = classDAO.trans_class_time(Double.parseDouble(end_Time));
		
		
		//DTO에 직접 한땀한땀 작업했습니다.
		subjectDTO.setSubject_No(subject_No);
		subjectDTO.setDepartment_Name(department_Name);
		subjectDTO.setSubject_Name(subject_Name);
		
		subjectDTO.setProfessor_Name(professor_Name);
		int professor_No = proDAO.find_pro_no(pro_department, professor_Name);	//교수님의 학과와 이름을 선택하면 그 값을 들고와서 db에 조회한 후 없을경우 교수 번호를 0으로 줬습니다.

		if(professor_No != 0) {
			subjectDTO.setProfessor_No(professor_No);
		}else {
			subjectDTO.setProfessor_No(0);
		}
		
		subjectDTO.setDay(day);
		subjectDTO.setGrade(grade);
		subjectDTO.setStart_Time(Double.parseDouble(start_Time));
		subjectDTO.setStart_Time_Output(start_Time_Output);
		subjectDTO.setEnd_Time(Double.parseDouble(end_Time));
		subjectDTO.setEnd_Time_Output(end_Time_Output);
		subjectDTO.setStudy_Time(study_Time);
		
		subjectDTO.setSubject_Type(subject_Type);
		subjectDTO.setSubject_Point(Integer.parseInt(subject_Point));
		subjectDTO.setStudent_Count(student_Count);
		
		int rs = subDAO.sub_regist(subjectDTO);
		departDAO.sub_count_plus(department_Name);
		
		String result = "등록 실패";
		if(rs != 0) {
			result = "등록 성공";
		}
		return result;
	}

	public void subject_list(Model model) {
		ArrayList<SubjectDTO> subjects = subDAO.sub_list();
		
		model.addAttribute("subjects", subjects);
	}
	
	public void sub_info(int subject_No, Model model) {
		SubjectDTO subject = subDAO.sub_info(subject_No);
		
		model.addAttribute("subject", subject);
	}
	
	
	public void subject_update_proc(String department_Name, String subject_Name, String pro_department,
			String professor_Name, String day, String grade, String start_Time, String end_Time, String subject_Type,
			String subject_Point, int student_Count, SubjectDTO subjectDTO, Model model, int subject_No) {
		
		DepartmentDTO depart = departDAO.depart_info(department_Name);
		
		subjectDTO.setSubject_No(subject_No);	//여기서 과목DTO로 직접 파싱하면서 설정했습니다.
		
		int professor_No = proDAO.find_pro_no(pro_department, professor_Name);

		if(professor_No != 0) {
			subjectDTO.setProfessor_No(professor_No);
		}else {
			subjectDTO.setProfessor_No(0);
		}
		
		
		
		subjectDTO.setDepartment_Name(department_Name);
		subjectDTO.setSubject_Name(subject_Name);
		subjectDTO.setProfessor_Name(professor_Name);
		
		subjectDTO.setDay(day);
		subjectDTO.setGrade(grade);
		
		subjectDTO.setStart_Time(Double.parseDouble(start_Time));
		String start_Time_Output = classDAO.trans_class_time(Double.parseDouble(start_Time));
		subjectDTO.setStart_Time_Output(start_Time_Output);

		String end_Time_Output = classDAO.trans_class_time(Double.parseDouble(end_Time));
		subjectDTO.setEnd_Time(Double.parseDouble(end_Time));
		subjectDTO.setEnd_Time_Output(end_Time_Output);
		
		int study_Time = (int) ((Double.parseDouble(end_Time) - Double.parseDouble(start_Time)));
		subjectDTO.setStudy_Time(study_Time);
		
		subjectDTO.setSubject_Type(subject_Type);
		subjectDTO.setSubject_Point(Integer.parseInt(subject_Point));
		subjectDTO.setStudent_Count(student_Count);
		
		
		int rs = subDAO.sub_update(subjectDTO);
		
		String result = "수정 실패";

		if (rs != 0) {
			result = "수정 성공";
		}
		
		model.addAttribute("result", result);
	}
	
	public void subject_delete(int subject_No, Model model) {
		//학과 삭제를 성공하면 해당하는 학과에 과목수를 -1 해는 부분
		departDAO.sub_count_minus(subDAO.sub_info(subject_No).getDepartment_Name());
		
		int rs = subDAO.sub_delete(subject_No);
		//SubjectDTO subjectDTO = subDAO. 
		
		String result = "삭제 실패";
		if(rs != 0) {
			result = "삭제 성공";
		}
		
		model.addAttribute("result", result);
	}

	
	//관리자의 강좌관리 부분 끝
	
		
}
