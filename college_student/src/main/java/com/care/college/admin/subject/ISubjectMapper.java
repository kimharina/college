package com.care.college.admin.subject;

import java.util.ArrayList;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ISubjectMapper {

	int sub_regist(SubjectDTO subjectDTO);

	ArrayList<SubjectDTO> sub_list();

	SubjectDTO sub_info(int subject_No);
	
	int sub_update(SubjectDTO subjectDTO);
	
	int sub_delete(int subject_No);

	
}
