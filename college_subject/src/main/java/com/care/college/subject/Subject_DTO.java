package com.care.college.subject;
/*
CREATE TABLE Subject_DB(
Subject_No INT,
Department_Name VARCHAR(100),
Subject_Name VARCHAR(100),
Professor_No INT,
Professor_Name VARCHAR(100),
Day VARCHAR(100),
Grade VARCHAR(100),
Start_Time DOUBLE,
End_Time DOUBLE,
Study_Time INT,
Subject_Type VARCHAR(100),
Subject_Point INT,
Student_Count INT);

ALTER TABLE Subject_DB ADD CONSTRAINT FK_Department_Name_Subject FOREIGN KEY (Department_Name) REFERENCES Department_DB (Department_Name) ON DELETE CASCADE;
ALTER TABLE Subject_DB ADD CONSTRAINT FK_Professor_No_Subject FOREIGN KEY (Professor_No) REFERENCES Professor_DB (Professor_No) ON DELETE CASCADE;
COMMIT;
 */
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class Subject_DTO {
    private int subject_No;
    private String department_Name;
    private String subject_Name;
    private int professor_No;
    private String professor_Name;
    private String day;
    private String grade;
    private double start_Time;
    private String start_Time_Output;
    private double end_Time;
    private String end_Time_Output;
    private int study_Time;
    private String subject_Type;
    private int subject_Point; 
    private int student_Count;
    private int table_Count;
    private int student_Count_ing;
    
    protected int studentNo;
    protected String studentName;
}