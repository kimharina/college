package com.care.college.admin.professor;

import java.util.ArrayList;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface IProfessorMapper {

	int pro_regist(ProfessorDTO professorDTO);

	ArrayList<ProfessorDTO> pro_list();

	ProfessorDTO pro_info(int professor_No);

	int pro_update(int professor_No, String department_New_Name, String professor_New_Name);

	int pro_delete(int professor_No);

	ArrayList<String> depart_pro_list(String department_Name);

	int find_pro_no(String pro_department, String professor_Name);

}