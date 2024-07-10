package com.care.college.student;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface StudentMapper_Student {

	StudentDTO_Student login(int no);

	int updateInfo(StudentDTO_Student student);

	int changePw(StudentDTO_Student student);

	int searchStNum(String name, String department, String tel);
	
	List<?> sendData(int student_No);
}












