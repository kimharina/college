package com.care.college.subject;


/*
	CREATE TABLE Subject_Cart_DB ( 
	Student_No INT Primary Key ,
	Student_Name VARCHAR(100),
	Department_Name VARCHAR(100),
	Subject_Name VARCHAR(100),
	Professor_No INT,
	Professor_Name VARCHAR(100),
	Grade INT,Day VARCHAR(100),
	Start_Time DOUBLE,Start_Time_Output VARCHAR(100),
	End_Time DOUBLE,End_Time_Output VARCHAR(100),
	Study_Time INT,
	Subject_Type VARCHAR(100),
	Subject_Point INT,
	Student_Count INT);
);
COMMIT;
 */


public class Cart_DTO extends Subject_DTO{
	private int student_no;
	private String Student_Name;

	private int subject_No;
	
    

	public int getStudent_No() {
		return student_no;
	}
	
	
	public void setStudent_No(int student_no) {
		this.student_no = student_no;
	}


	public String Student_Name() {
		return Student_Name;
	}



	public void setStudent_Name(String Student_Name) {
		this.Student_Name = Student_Name;
	}



    public int getSubject_No() {
        return subject_No;
    }

    public void setSubject_No(int subject_No) {
        this.subject_No = subject_No;
    }

}
