<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>강좌 등록</title>

</head>
<body>
<div class="center">
	<h1>강좌 등록하기</h1>
	<form action="/student/subject_regist_proc" method='post' id="f">
		<label>학과 선택</label> <select name="department_Name"
			id="department_Name">
			<c:forEach var="depart" items="${departments }">
				<option value="${depart.department_Name }">${depart.department_Name }</option>
			</c:forEach>
		</select> <br>

		<table class="table">
			<tr>
				<th>강좌 이름</th>
				<td><input type="text" name="subject_Name" id="subject_Name"
					placeholder="강좌 이름"></td>
			</tr>
			<tr>
				<th>담당 교수 학과 선택</th>
				<td><select name="pro_department" id="pro_department">
						<c:forEach var="depart" items="${departments }">
							<option value="${depart.department_Name }">${depart.department_Name }</option>
						</c:forEach>
				</select></td>
			</tr>
			<tr>
				<th>강의 교수 선택</th>
				<td><select name="professor_Name" id="professor_Name">
						<c:forEach var="pro" items="${professors}">
							<option value="${pro.professor_Name }">${pro.professor_Name }</option>
						</c:forEach>
				</select></td>
			</tr>
			<tr>
				<th>요일 선택</th>
				<td><select name="day" id="day">
						<option value="월요일">월요일</option>
						<option value="화요일">화요일</option>
						<option value="수요일">수요일</option>
						<option value="목요일">목요일</option>
						<option value="금요일">금요일</option>
				</select></td>
			</tr>
			<tr>
				<th>학년 선택</th>
				<td><select name="grade" id="grade">
						<option value="1학년">1학년</option>
						<option value="2학년">2학년</option>
						<option value="3학년">3학년</option>
						<option value="4학년">4학년</option>
				</select></td>
			</tr>
			<tr>
				<th>시작 시간</th>
				<td><select name="start_Time" id="start_Time">
						<c:forEach var="time" items="${classTime}">
							<option value="${time.class_Time_Code}">${time.class_Time}</option>
						</c:forEach>
				</select></td>
			</tr>
			<tr>
				<th>종료 시간</th>
				<td><select name="end_Time" id="end_Time">
						<c:forEach var="time" items="${classTime}">
							<option value="${time.class_Time_Code}">${time.class_Time}</option>
						</c:forEach>
				</select></td>
			</tr>
			<tr>
				<th>강좌 유형</th>
				<td><select name="subject_Type" id="subject_Type">
						<option value="전공필수">전공필수</option>
						<option value="전공선택">전공선택</option>
						<option value="교양과목">교양과목</option>
				</select></td>
			</tr>
			<tr>
				<th>학점 선택</th>
				<td><select name="subject_Point" id="subject_Point">
						<option value="2">2학점</option>
						<option value="3">3학점</option>
						<option value="4">4학점</option>
				</select></td>
			</tr>
			<tr>
				<td colspan="2"><input type="number" name="student_Count"
					id="student_Count" placeholder="1~50명" min="1" max="50" value="50">학생
					정원(1~50명)</td>
			</tr>
			<tr>
				<td colspan="2">
					<button type="button" class="custom-btn btn-5" onclick="allCheck()">
						<span>등록하기</span>
					</button>
					<button type="button" class="custom-btn btn-5"
						onclick="location.href='/student/admin_index'">
						<span>이전으로</span>
					</button>
				</td>
			</tr>
		</table>
	</form>
</div>
</body>
<style>
.center {
	text-align: center; /* body의 텍스트를 중앙으로 정렬합니다. */
}

h1 {
	display: inline-block; /* 가운데 정렬을 위해 inline-block 사용 */
	margin: 3px auto; /* 좌우 마진을 auto로 설정하여 수평 중앙 정렬 */
}
/* 선택 목록 스타일 */
select {
	width: 150px;
	padding: 4px;
	margin: 3px auto; /* 위아래 여백 추가 */
	box-sizing: border-box;
	text-align: center;
}

/* 라벨 스타일 */
label {
	margin-top: 5px;
}
/* 더 나은 레이아웃을 위해 flexbox를 적용합니다. */
#f {
	display: flex;
	flex-direction: column;
	align-items: center;
}

/* 테이블 스타일 */
.table {
	border: 1;
	border-collapse: collapse;
	width: 40%;
	margin-top: 20px;
}

th, td {
	padding: 5px;
	border: 1px solid #ddd;
	text-align: center;
}

th {
	background-color: #f2f2f2;
}

/* 입력 필드 스타일 */
input[type="text"] {
	width: 55%;
	padding: 8px;
	margin: 3px auto; /* 위아래 여백 추가 */
	box-sizing: border-box;
	text-align: center;
}
/* 입력 필드 스타일 */
input[type="number"] {
	width: 30%; /* 크기 조절 */
	padding: 8px;
	box-sizing: border-box;
	margin: 3px auto; /* 위아래 여백 추가 */
	display: block; /* 가운데 정렬을 위해 block 요소로 변경 */
	text-align: center; /*글씨 가운데 정렬*/
}

/*하단 버튼 2개 css*/
.frame {
	margin: 40px auto;
	text-align: center;
}

button {
	margin: 7px;
	outline: none;
}

.custom-btn {
	margin-right: 40px; /* 버튼 간격 조정 */
	width: 130px;
	height: 40px;
	padding: 10px 25px;
	border: 2px solid #000;
	font-family: 'Lato', sans-serif;
	font-weight: 500;
	background: transparent;
	cursor: pointer;
	transition: all 0.3s ease;
	position: relative;
	display: inline-block;
}
/* 커스텀 버튼 디자인 */
.btn-5 {
	background: #001F3F;
	color: #fff;
	line-height: 42px;
	padding: 0;
	border: none;
}

.btn-5:hover {
	background: transparent;
	color: #000;
	box-shadow: -7px -7px 20px 0px #fff9, -4px -4px 5px 0px #fff9, 7px 7px
		20px 0px #0002, 4px 4px 5px 0px #0001;
}

.btn-5:before, .btn-5:after {
	content: '';
	position: absolute;
	top: 0;
	right: 0;
	height: 2px;
	width: 0;
	background: #000;
	transition: 400ms ease all;
}

.btn-5:after {
	right: inherit;
	top: inherit;
	left: 0;
	bottom: 0;
}

.btn-5:hover:before, .btn-5:hover:after {
	width: 100%;
	transition: 800ms ease all;
}
</style>
<script>
	function allCheck(){
		
		var department_Name = document.getElementById('department_Name');
		var subject_Name = document.getElementById('subject_Name');
		var pro_department = document.getElementById('pro_department');
		var professor_Name = document.getElementById('professor_Name');
		var day = document.getElementById('day');
		var grade = document.getElementById('grade');
		var start_Time = document.getElementById('start_Time');
		var end_Time = document.getElementById('end_Time');
		var subject_Type = document.getElementById('subject_Type');
		var subject_Point = document.getElementById('subject_Point');
		var student_Count = document.getElementById('student_Count');
		
		
		if (department_Name.value == "") {
			alert('학과명은 필수 항목입니다.');
		} else if (subject_Name.value == "") {
			alert('강좌명은 필수 항목입니다.');
		 } else {
		        // 시간 비교를 위해 입력된 시작시간과 종료시간을 부동 소수점 숫자로 변환
		        var startTime = parseFloat(start_Time.value);
		        var endTime = parseFloat(end_Time.value);

		        // 시간 비교
		        if (endTime - startTime < 0.5) {
		            alert('시작시간과 종료시간을 확인해주세요');
		        } else {
		            var f = document.getElementById('f');
		            f.submit();
		        }
		    }
		}
</script>
</html>