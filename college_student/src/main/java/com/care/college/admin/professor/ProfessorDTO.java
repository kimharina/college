package com.care.college.admin.professor;

public class ProfessorDTO {
	private int professor_No;
	private String professor_Name;
	private String department_Name;
	
	public int getProfessor_No() {
		return professor_No;
	}
	public void setProfessor_No(int professor_No) {
		this.professor_No = professor_No;
	}
	public String getProfessor_Name() {
		return professor_Name;
	}
	public void setProfessor_Name(String professor_Name) {
		this.professor_Name = professor_Name;
	}
	public String getDepartment_Name() {
		return department_Name;
	}
	public void setDepartment_Name(String department_Name) {
		this.department_Name = department_Name;
	}
}
