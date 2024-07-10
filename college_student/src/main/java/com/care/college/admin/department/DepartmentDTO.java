package com.care.college.admin.department;

public class DepartmentDTO {
	private int department_No;
	private String department_Name;
	private int student_Count;
	private int subject_Count;
	
	public int getDepartment_No() {
		return department_No;
	}
	public void setDepartment_No(int department_No) {
		this.department_No = department_No;
	}
	public String getDepartment_Name() {
		return department_Name;
	}
	public void setDepartment_Name(String department_Name) {
		this.department_Name = department_Name;
	}
	public int getStudent_Count() {
		return student_Count;
	}
	public void setStudent_Count(int student_Count) {
		this.student_Count = student_Count;
	}
	public int getSubject_Count() {
		return subject_Count;
	}
	public void setSubject_Count(int subject_Count) {
		this.subject_Count = subject_Count;
	}
}
