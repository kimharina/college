package com.care.college.subject;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class SubjectScheduleDTO {
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
    
    protected int studentNo;
    protected String studentName;
}
