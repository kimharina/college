package com.care.college.admin.subject;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface IClassTimeMapper {

	List<Class_time_dbDTO> get_Class_Time();
	
	String trans_class_time(double class_Time_Code);
}
