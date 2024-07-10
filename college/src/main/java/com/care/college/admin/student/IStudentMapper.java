package com.care.college.admin.student;

import java.util.ArrayList;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface IStudentMapper {

	int stu_regist(StudentDTO studentDTO);

	ArrayList<StudentDTO> stu_list();

	StudentDTO stu_info(int student_No);

	int stu_update(StudentDTO studentDTO);

	int stu_delete(int student_No);

}
