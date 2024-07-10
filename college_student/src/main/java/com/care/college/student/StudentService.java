package com.care.college.student;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Service
public class StudentService {
	@Autowired private StudentMapper_Student mapper;
	@Autowired private HttpSession session;
	
	public String loginProc(String student_no, String password, Model model) {

		if (student_no == null || student_no.trim().isEmpty())
			return "학번을 입력하세요.";
		if (password == null || password.trim().isEmpty())
			return "비밀번호를 입력하세요.";

		int no = Integer.parseInt(student_no);
		
		//관리자가 로그인할 경우(학번0)
		if (student_no.trim().equals("0")) {
			StudentDTO_Student check_admin = mapper.login(no);
			if (check_admin != null && password.equals("admin") == true) {	
				return "관리자입니다.";
			}
		}
		
		//비번이 7자리면 비밀번호 변경 아니면 로그인성공
		StudentDTO_Student check = mapper.login(no);
		if (password.length() == 7) {
			if (check != null && password.equals(check.getPassword()))				
				return "비밀번호를 변경해주세요.";
			return "학번 또는 비밀번호를 확인 후 다시 입력하세요.";
			
		} else {
			BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
			if (check != null && encoder.matches(password, check.getPassword()) == true)
				return "로그인 성공";
		return "학번 또는 비밀번호를 확인 후 다시 입력하세요.";
		}
		
	}

	public StudentDTO_Student myInfo(int student_no) {
		StudentDTO_Student student = mapper.login(student_no);
		return student;
	}

	public String updateInfo(StudentDTO_Student student) {
		
		if (student.getTel() == null || student.getTel().trim().isEmpty()) {
			return "전화번호를 입력하세요.";
		} else if(student.getEmail() == null || student.getEmail().trim().isEmpty()) {
			return "이메일을 입력하세요.";
		} else if(student.getBirth() == null || student.getBirth().trim().isEmpty()) {
			return "생년월일을 입력하세요.";
		} else if(student.getAddress() == null || student.getAddress().trim().isEmpty()) {
			return "주소를 입력하세요.";
		}

		int result = mapper.updateInfo(student);
		if (result == 1)
			return "학생정보 수정 완료";

		return "정보수정을 다시 시도하세요.";
	}

	public String changePw(StudentDTO_Student student, String pw) {	
		/* 암호화 과정 */
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String secretPass = encoder.encode(pw);
		
		student.setPassword(secretPass);
		
		int result = mapper.changePw(student);
		
		if (result == 1)
			return "비밀번호가 변경되었습니다.";

		return "다시 입력해주세요.";
	}

	public int searchStNum(String name, String department, String tel, Model model ) {
		
		int result = mapper.searchStNum(name, department, tel);
		if(result == 0) {
			String url = "searchStNum";
			String alert = "해당하는 학생이 없습니다.";
			model.addAttribute("url", url);
			model.addAttribute("alert", alert);
		}

		return result;
	}
	
	public String loginCheck(HttpSession session) {
		System.out.println(session.getAttribute("student_No"));
		String student_No = (String)session.getAttribute("student_No");
		return student_No;
	}


	    
}

