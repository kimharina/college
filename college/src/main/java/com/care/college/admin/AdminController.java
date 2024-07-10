package com.care.college.admin;

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
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.care.college.JWT.AuthConstants;
import com.care.college.JWT.JwtTokenProvider;
import com.care.college.admin.department.DepartmentDTO;
import com.care.college.admin.professor.ProfessorDTO;
import com.care.college.admin.student.StudentDTO;
import com.care.college.admin.subject.Class_time_dbDTO;
import com.care.college.admin.subject.SubjectDTO;


@Controller
public class AdminController {
	@Autowired private AdminService service;
	private final JwtTokenProvider JwtTokenProvider;

    public AdminController(JwtTokenProvider JwtTokenProvider) {
        this.JwtTokenProvider = JwtTokenProvider;
    }
	
	@RequestMapping("/student/admin_index")
	public String admin_index() {
		return "admin/admin_index";
	}
    @ResponseBody   
    @PostMapping("/student/adminCheck")
    public ResponseEntity loginCheck(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token,
    		Model model) {
    	System.out.println("토큰"+token);
    	if (token != null && token.startsWith("BEARER ")) {
    		String jwtToken = token.substring(7); 						// "Bearer " 이후의 부분
    		boolean check = JwtTokenProvider.isValidToken(jwtToken);	// 여기서 jwtToken을 검증하고 필요한 작업 수행
    		if (check) {
    			Map<String, Object> response = new HashMap<>();
    			HttpHeaders headers = new HttpHeaders();
    			
    			headers.add(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + jwtToken);	//http헤더로 보내기
    			String name = JwtTokenProvider.parseTokenToName(jwtToken); 							//name 추출
    			if(name.equals("admin")) {
    				response.put("name", name);
    				var authorizationHeader = headers.getFirst(AuthConstants.AUTH_HEADER);
    				// response.headers에서 'Authorization' 헤더를 가져온다.
    			
    				return new ResponseEntity<>(response, headers, HttpStatus.OK);		// HttpHeaders 및 데이터를 함께 전송
    			}
    			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("관리자가 아닙니다.");

    		} else {
    			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 유효하지 않습니다.");
    		}
    	}
    	return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰이 없습니다.");
    }
	
	//관리자의 학과 관리 부분
	//학과 등록
	@RequestMapping("/student/department_regist")
	public String department_regist() {
		return "admin/department/department_regist";
	}
	
	@PostMapping("/student/department_regist_proc")
	public String department_regist_proc(DepartmentDTO departmentDTO, Model model) {
		if(departmentDTO.getDepartment_Name()== null || departmentDTO.getDepartment_Name().trim().isEmpty()) {
			return "redirect:department_regist";
		}
			 
		String result = service.department_regist_proc(departmentDTO);
		
		if(result.equals("등록 실패")) {
			model.addAttribute("result", result);
			return "admin/department/department_regist";
		}else {
			return "redirect:department_list";
		}
	}
	
	//학과목록을 보여주고 학과를 클릭하면 해당 학과의 교수님과 학생들을 볼 수 있게 구현
	@RequestMapping("/student/department_list")
	public String department_list(Model model) {
		
		service.department_list(model);
		return "admin/department/department_list";
	}
	
	//학과의 세부정보(학생,교수,인원)
	@RequestMapping("/student/department_detail_info")
	public String department_detail_info(String department_Name, Model model) {
		service.department_detail_info(department_Name, model);

		return "admin/department/department_detail_info";
	}
	
	//학과 수정페이지로 이동 - 서비스에서 모델에 해당학과 데이터 DTO로 담아서 보내줌
	@GetMapping("/student/department_update")
	public String department_update(String department_Name, Model model) {
		service.department_info(department_Name, model);
		
		return "admin/department/department_update";
	}
	//학과 수정페이지에서 url에 학과의 이름과 학과코드를 갖고와서 처리함
	@PostMapping("/student/department_update_proc")
	public String department_update_proc(Model model, String department_New_Name, int department_No) {
		service.department_update_proc(model, department_New_Name, department_No);
		
		return "admin/admin_index";
	}
	
	//학과 삭제
	@RequestMapping("/student/department_delete")
	public String department_delete(String department_Name, Model model) {
		service.department_delete(department_Name, model);
		
		return "redirect:admin_index";
	}
	
	
	//관리자의 교수 관리 부분
	//교수 등록페이지 이동시 학과들을 모델에 담아서 가져감
	@RequestMapping("/student/professor_regist")
	public String professor_regist(Model model) {
		service.department_list(model);
		return "admin/professor/professor_regist";
	}
	
	@PostMapping("/student/professor_regist_proc")
	public String professor_regist_proc(ProfessorDTO professorDTO, Model model) {
		if(professorDTO.getDepartment_Name() == null || professorDTO.getDepartment_Name().trim().isEmpty() ||
			professorDTO.getProfessor_Name() == null || professorDTO.getProfessor_Name().trim().isEmpty()	) {
			return "redirect:professor_regist";
		}
		String result = service.professor_regist_proc(professorDTO);
		
		if(result.equals("등록 실패")) {
			model.addAttribute("result", result);
			return "admin/professor/professor_regist";
		}else {
			return "redirect:professor_list";
		}
	}
	
	//교수 목록 - 페이지로 나눠서 한 페이지별로 보여주고 학과별정렬, 이름검색 기능 필요 professor_list
	@RequestMapping("/student/professor_list")
	public String professor_list(Model model) {
		service.professor_list(model);
		
		return "admin/professor/professor_list";
	}
	
	//교수 정보 수정
	@RequestMapping("/student/professor_update")
	public String professor_update(Model model, int professor_No) {
		service.department_list(model);
		service.professor_info(model, professor_No);
		
		return "admin/professor/professor_update";
	}
	@PostMapping("/student/professor_update_proc")
	public String professor_update_proc(String department_New_Name, String professor_New_Name, int professor_No, Model model) {
		service.professor_update_proc(department_New_Name, professor_New_Name, professor_No, model);
		
		return "redirect:admin_index";
	}
	
	//교수 삭제
	@RequestMapping("/student/professor_delete")
	public String professor_delete(int professor_No, Model model) {
		service.professor_delete(professor_No, model);
		
		return "admin/admin_index";
	}
	
	
	//관리자의 학생 관리 부분
	//학생 등록. 초기에 이동할 때 학과들의 리스트를 model에 담아서 가져감
	@RequestMapping("/student/student_regist")
	public String student_regist(Model model) {
		service.department_list(model);
		return "admin/student/student_regist";
	}
	
	@PostMapping("/student/student_regist_proc")
	public String student_regist_proc(StudentDTO studentDTO, String years, Model model) {
		if(studentDTO.getDepartment_Name() == null || studentDTO.getDepartment_Name().trim().isEmpty() ||
			studentDTO.getName() == null || studentDTO.getName().trim().isEmpty() ||
			years == null || years.trim().isEmpty() || 
			studentDTO.getGrade() == null || studentDTO.getGrade().trim().isEmpty() ||
			studentDTO.getPassword() == null || studentDTO.getPassword().trim().isEmpty() ||
			studentDTO.getTel() == null || studentDTO.getTel().trim().isEmpty() ||
			studentDTO.getBirth() == null || studentDTO.getBirth().trim().isEmpty() ||
			studentDTO.getEmail() == null || studentDTO.getEmail().trim().isEmpty() ||
			studentDTO.getAddress() == null || studentDTO.getAddress().trim().isEmpty() 		) {
				return "redirect:student_regist";
			}

		    int intValue = Integer.parseInt(years);
		    System.out.println("years: "+years);

		String result = service.student_regist_proc(studentDTO, intValue);
		
		if(result.equals("등록 실패")) {
			model.addAttribute("result", result);
			return "admin/student/student_regist";
		}else {
			return "redirect:student_list";
		}
	}
	
	//학생들 목록 보기
	@RequestMapping("/student/student_list")
	public String student_list(Model model) {
		service.student_list(model);
		
		return "admin/student/student_list";
	}
	
	//학생의 세부 정보 보기
	@RequestMapping("/student/student_info")
	public String student_info(int student_No, Model model) {
		service.student_info(student_No, model);
		
		return "admin/student/student_info";
	}
	
	//학생의 정보 변경
	@RequestMapping("/student/student_update")
	public String student_update(int student_No, Model model) {
		service.department_list(model);
		service.student_info(student_No, model);
		
		return "admin/student/student_update";
	}
	
	@RequestMapping("/student/student_update_proc")
	public String student_update_proc(String student_num, String name, String department_Name, String grade,
			String tel, String email, String birthday, String address, String pw, StudentDTO studentDTO, Model model) {
		//생각한대로 진행이 안되어서 단순작업으로 했습니다.
		if(name == null || name.trim().isEmpty() ||
				pw == null || pw.trim().isEmpty() ||
				department_Name == null || department_Name.trim().isEmpty() || 
				grade == null || grade.trim().isEmpty() ||
				tel == null || tel.trim().isEmpty() ||
				email == null || email.trim().isEmpty() ||
				address == null || address.trim().isEmpty() 	) {
					return "redirect:student_update?student_No="+student_num;
				}
		service.student_update_proc(student_num, name, department_Name, grade, tel, email, birthday, address, pw, studentDTO, model);
		
		return "redirect:student_list";
	}
	
	// 학생 삭제
	@RequestMapping("/student/student_delete")
	public String student_delete(int student_No, Model model) {
		service.student_delete(student_No, model);

		return "redirect:student_list";
	}
	
	
	//관리자의 강의 관리 부분
	//강의를 등록하기 전에 시간들을 테이블에 구성해두고 불러와서 사용
	
	
	//강의 등록
	@RequestMapping("/student/subject_regist")
	public String subject_regist(Model model) {
		List<Class_time_dbDTO> classTime = new ArrayList<Class_time_dbDTO>();
		
		service.department_list(model);
		service.professor_list(model);
		classTime = service.get_Class_Time();
		
		model.addAttribute("classTime", classTime);
		return "admin/subject/subject_regist";
	}
	
	@RequestMapping("/student/subject_regist_proc")
	public String subject_regist_proc(String department_Name, String subject_Name, String pro_department, String professor_Name, String day, @RequestParam(required = false) String grade, String start_Time, String end_Time,
			String subject_Type, String subject_Point, int student_Count, SubjectDTO subjectDTO, Model model) {
		
		String result = service.subject_regist_proc(department_Name, subject_Name, pro_department, professor_Name, grade, day, start_Time, end_Time, subject_Type, subject_Point, student_Count, subjectDTO, model);
		
		if(result.equals("등록 실패")) {
			model.addAttribute("result", result);
			return "admin/subject/subject_regist";
		}else {
			return "redirect:subject_list";
		}
	}

	//강의 목록
	@RequestMapping("/student/subject_list")
	public String subject_list(Model model) {
		service.subject_list(model);
		
		return "admin/subject/subject_list";
	}
	
	//강의 수정
	@RequestMapping("/student/subject_update")
	public String subject_update(int subject_No, Model model) {
		List<Class_time_dbDTO> classTime = new ArrayList<Class_time_dbDTO>();
		
		service.sub_info(subject_No, model);	//수정할 강좌의 정보를 모델로 담아서 가져옴
		service.department_list(model);	//학과들의 정보와
		service.professor_list(model);	//교수들의 정보
		
		classTime = service.get_Class_Time();
		model.addAttribute("classTime", classTime);
		
		return "admin/subject/subject_update";
	}
	
	@RequestMapping("/student/subject_update_proc")
	public String subject_update_proc(String department_Name, String subject_Name, String pro_department, String professor_Name, String day, String grade, String start_Time, String end_Time,
			String subject_Type, String subject_Point, int student_Count, SubjectDTO subjectDTO, Model model, int subject_No) {
		
		
		service.subject_update_proc(department_Name, subject_Name, pro_department, professor_Name, day, grade, start_Time, end_Time,
				subject_Type, subject_Point, student_Count, subjectDTO, model, subject_No);
		
		return "redirect:subject_list";
	}
	
	//강의 삭제
	@RequestMapping("/student/subject_delete")
	public String subject_delete(int subject_No, Model model) {
		service.subject_delete(subject_No, model);
		
		return "redirect:subject_list";
	}
}
