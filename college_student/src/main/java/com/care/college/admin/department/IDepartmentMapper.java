package com.care.college.admin.department;

import java.util.ArrayList;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface IDepartmentMapper {
	
	int depart_getMaxNum();
	
	int depart_regist(DepartmentDTO departmentDTO);
	
	ArrayList<DepartmentDTO> depart_list();

	DepartmentDTO depart_info(String department_Name);
	
	void student_count_plus(String department_Name);
	
	void student_count_minus(String department_Name);
	
	void sub_count_plus(String department_Name);
	
	void sub_count_minus(String department_Name);
	
	int depart_update(int department_No, String department_New_Name);

	int depart_delete(String department_Name);

}
