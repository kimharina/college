<%@ page language="java" contentType="text/html; charset=UTF-8"  pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<%@ include file="../sideBar.jsp"%>

<style>
    .day-header {
        width: 30%;
        border: 1px solid gray;
        text-align: center;
        background-color: white;
    }
    tr, th, td{
    	height: 33px;
    }
    .time {
    	width: 10px; 
    	border: 1px solid gray; 
    	text-align: center; 
    	background-color: ="white";
    }
    .day {
    	width: 50px; 
    	border: 0px solid gray;
    	border-right: 1px solid rgba(128, 128, 128, 0.5);
    }
    .day_hide {
    	width: 80px; 
    	border-bottom: 1px solid rgba(128, 128, 128, 0.5); 
    	border-right: 1px solid rgba(128, 128, 128, 0.5);
    }

</style>

		<div id="contents" class="contents">
			<div style="margin-left: 10px; margin-top: 10px">
			<table style="width: 800px; border-collapse: collapse; border: 1px solid gray;">
				<thead>
		          <tr id="dayRow">
		            <th style="width: 100px; border: 1px solid gray; text-align: center;" bgcolor="white">시간</th>
		          </tr>
		        </thead>
				<tbody id="tableBody">
			    </tbody>
			</table>
			</div>
		</div>
</body>
	<script>	

			// 응답 객체에서 Authorization 헤더를 가져오기
			var jwtToken = localStorage.getItem("Authorization");

			console.log('jwtToken : '+jwtToken);

			//토큰이 있다면 서버로 전송
			if (jwtToken) {
				let student_Schedule, time_Table_Color, time_Table_Day, time_Table_Time;

			     fetch('/sugang/timeTable', {
			         method: 'POST',
			         headers: {
			         	'Content-Type': 'application/json',
			         	 Authorization: localStorage.getItem('Authorization'),
		            },

			     })
 			    .then(response => {
			        // HTTP 상태 코드가 200 OK인 경우
			        if (response.ok) {
			            // Content-Type이 application/json인 경우
			            if (response.headers.get('Content-Type').includes('application/json')) {
			                return response.json(); // JSON 형식으로 파싱
			            } else {
			                return response.text(); // 다른 형식의 데이터는 텍스트로 직접 받음
			            }
			        } else {
			            throw new Error('Network response was not ok.');
			        }
			    })
			   .then(response => {
			       // 받은 JSON 데이터를 변수에 할당
					if (response) {
		            	console.log(response);
		                // 각 항목에 대한 데이터 가져오기
		                student_Schedule = response.student_Schedule;
			            time_Table_Color = response.time_Table_Color;
			            time_Table_Day = response.time_Table_Day;
			            time_Table_Time = response.time_Table_Time;
 		                
			           /*  console.log(student_Schedule);
			            console.log(time_Table_Color);
			            console.log(time_Table_Day);
			            console.log(time_Table_Time);  */
			            
			         // 화면에 시간표를 그리는 로직
			            drawTimeTable(time_Table_Color, student_Schedule, time_Table_Day, time_Table_Time);
					} else {
			        	console.log(data);
			            localStorage.removeItem("Authorization");
			            alert("로그인 해주세요.");
			            window.location.href = '/student/login';
			    	}
			   })
			    .catch(error => {
			            // 에러 처리
			            console.error('토큰 검증 실패:', error);
			            localStorage.removeItem("Authorization");
			            alert("다시 로그인 해주세요.");	
			            window.location.href = '/student/login';
			    });
		    } else {
			     // 토큰이 없을 경우의 처리
			     console.log('토큰이 없습니다.');
			     localStorage.removeItem("Authorization");
			     alert("다시 로그인 해주세요.");
		         window.location.href = '/student/login';
			};


			// 시간표를 그리는 함수
			function drawTimeTable(time_Table_Color, student_Schedule, time_Table_Day,time_Table_Time) {
			 	 var time_Table_Color = time_Table_Color ? time_Table_Color : [];
				 var student_Schedule = student_Schedule ? student_Schedule : []; 
				 
				    if (student_Schedule.length === 0) {
				        console.log('Invalid schedule format: Empty schedule array');
				        return;
				    }
				// 요일 헤더 삽입
			        const dayRow = document.getElementById("dayRow");
			        time_Table_Day.forEach((day, index) => {
			          const thElement = document.createElement("th");
			          thElement.textContent = day;
			          thElement.classList.add("day-header"); // 클래스 추가
			          dayRow.appendChild(thElement);
			        });
			    // 시간과 테이블 셀 삽입
			        const tableBody = document.getElementById("tableBody");
			        
			       	time_Table_Time.forEach(time => {
			       		if(time % 1.0 ==0){
				          const trElement = document.createElement("tr");
				          const thTime = document.createElement("th");
				          thTime.textContent = time+`시`;
				          thTime.classList.add("time"); // 클래스 추가
				          thTime.setAttribute("rowspan", "2"); // rowspan 추가
				          trElement.appendChild(thTime);

				          time_Table_Day.forEach(day => {

				            const td1Element = document.createElement("td");
				            td1Element.classList.add("day"); // 클래스 추가
				            td1Element.setAttribute("id", day+`_`+time.toFixed(1));
				            trElement.appendChild(td1Element);
				          });
				          
				          const tr2Element = document.createElement("tr");
				          time_Table_Day.forEach(day => {
				            const td2Element = document.createElement("td");
				            td2Element.classList.add("day_hide"); // 클래스 추가
				            td2Element.setAttribute("id", day+`_`+(time+0.5));
				            tr2Element.appendChild(td2Element);
				          });
	
				          tableBody.appendChild(trElement);
				          tableBody.appendChild(tr2Element);
			      		}     
			       });
			        	
			  
				    student_Schedule.forEach(function (schedule) {

			        const random_Color = time_Table_Color[Math.floor(Math.random() * time_Table_Color.length)];
			        
			        let start_Time = schedule.start_Time;
			        
			        var day = schedule.day;
			        console.log('day', day);
			        var subject_Start = null;
			        
			        // 과목 시작 시간 구분 Id 생성   
			        if(start_Time % 1 === 0 ){

			        	var format_Time = start_Time.toFixed(1); // "10.0"식으로 문자 처리

			        	subject_Start = schedule.day+'_'+format_Time;
			        }else{
			        	subject_Start = schedule.day+'_'+schedule.start_Time;
			        }

			        console.log('subject_Start', subject_Start);
					
			        for (let j = 0; j < schedule.table_Count; j++) {
			        	
			        	if(start_Time % 1 === 0 ){
			        		var format_Time = start_Time.toFixed(1); // "10.0"식으로 문자 처리
			        		var count_Id = day + '_' + format_Time;
			            } else {
			        		var count_Id = day + '_' + start_Time; 	
			           		console.log('count_Id', count_Id);
			        	}  
			            
			        	console.log('cell', count_Id);
			        	
			            var cell = document.getElementById(count_Id);
				          if (cell) { 
				          	if(count_Id == subject_Start){
				           		cell.innerText = schedule.subject_Name;
				          		cell.style.fontFamily = "Arial, sans-serif";
				          		cell.style.fontSize = "13px";
				          		cell.style.fontWeight = "bold";
				          		cell.style.color = "#333"; 		
				           		console.log('count_Id', count_Id);
				          	}
			          		                
			           
			                cell.style.backgroundColor = random_Color;
			                
			                if (cell.style.backgroundColor !== 'white') {
			                    cell.style.borderBottom = 'none';
			                }
			            }

			            start_Time += 0.5;
			        }
			    });
			}

		    

</script>

</html>