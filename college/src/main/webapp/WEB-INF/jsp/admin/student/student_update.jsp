<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<script>
	function allCheck() {
		var name = document.getElementById('name');
		var pw = document.getElementById('pw');
		var department_Name = document.getElementById('department_Name');
		var grade = document.getElementById('grade');

		var student_num = document.getElementById('student_num');
		var tel = document.getElementById('tel');
		var email = document.getElementById('email');

		var birthday = document.getElementById('birthday');
		var address = document.getElementById('address');

		if (name.value == "") {
			alert('이름은 필수 항목입니다.');
		} else if (pw.value == "") {
			alert('비밀번호는 필수 항목입니다.');
		} else if (department_Name.value == "") {
			alert('학과는 필수 항목입니다.');
		} else if (grade.value == "") {
			alert('학년은 필수 항목입니다.');
		} else if (tel.value == "") {
			alert('전화번호는 필수 항목입니다.');
		} else if (email.value == "") {
			alert('이메일은 필수 항목입니다.');
		} else if (address.value == "") {
			alert('주소는 필수 항목입니다.');
		} else {
			var f = document.getElementById('f');
			f.submit();
		}
	}
</script>
<head>
<meta charset="UTF-8">
<title>학생 정보 수정</title>
</head>
<body>
<div class="center">
	<h1>학생 정보 수정하기</h1>
	<form action="student_update_proc" method="get" id="f">
		<table class="table">
			<tr>
				<th>학번</th>
				<th>이름</th>
				<th>학과명</th>
				<th>학년</th>
			</tr>
			<tr>
				<td><input name="student_num" id="student_num"
					value="${student.student_No}" readonly="readonly" /></td>
				<td><input name="name" id="name" placeholder="${student.name}" /></td>
				<td><select name="department_Name" id="department_Name">
						<c:forEach var="depart" items="${departments }">
							<option value="${depart.department_Name }">${depart.department_Name }</option>
						</c:forEach>
				</select></td>
				<td><select name="grade" id="grade">
						<option value="">== 학년선택 ==</option>
						<option value="1학년">1학년</option>
						<option value="2학년">2학년</option>
						<option value="3학년">3학년</option>
						<option value="4학년">4학년</option>
				</select></td>
			</tr>

			<tr>
				<th>비밀번호</th>
				<th>전화번호</th>
				<th>e-mail</th>
			</tr>
			<tr>
				<td><input type="text" name="pw" id="pw" placeholder="비밀번호" /></td>
				<td><input type="text" name="tel" id="tel"
					placeholder="${student.tel}" /></td>
				<td><input type="text" name="email" id="email"
					placeholder="${student.email}" /></td>
			</tr>

			<tr>
				<th>생년월일</th>
				<th>주소</th>
				<th colspan="2">수정 &nbsp;&nbsp;||&nbsp;&nbsp; 초기화</th>
			</tr>
			<tr>
				<td><input type="number" name="birthday" id="birthday"
					placeholder="${student.birth}" /></td>
				<td><input type="text" name="address" id="address"
					placeholder="${student.address}" /></td>
				<td>
					<button class="custom-btn btn-5" onclick="allCheck()">
						<span>수정하기</span>
					</button>
				</td>
				<td>
					<button class="custom-btn btn-5" type="reset">
						<span>초기화</span>
					</button>
				</td>
			</tr>
		</table>
	</form>
	<button type="button" onclick="location.href='/student/student_list'">
		<img src="/img/admin/back.png" alt="이전으로 가기"> <span>이전으로 가기</span>
	</button>
</div>
</body>
<style>
.center {
	text-align: center; /* body의 텍스트를 중앙으로 정렬합니다. */
}

h1 {
	display: inline-block; /* 가운데 정렬을 위해 inline-block 사용 */
	margin: 5px auto; /* 좌우 마진을 auto로 설정하여 수평 중앙 정렬 */
}

/* 학번과 이름 스타일 설정 */
#student_num, #name {
	width: 150px; /* 원하는 크기로 설정 */
	padding: 3px; /* 내부 여백 설정 */
	text-align: center;
	border: 1px solid #ccc; /* 테두리 스타일 및 색상 설정 */
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
	width: 70%;
	margin-top: 20px;
	margin-bottom: 20px;
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
	width: 55%; /* 크기 조절 */
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
	margin: 3px;
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

/* 뒤로가기 이미지 스타일 */
button img {
	width: 20px; /* 원하는 크기로 조절 */
	height: 20px; /* 원하는 크기로 조절 */
	margin-right: 5px; /* 이미지와 텍스트 간격 조절 */
}
/* alt 텍스트 스타일 */
button img+span {
	font-weight: bold; /* alt 텍스트 두껍게 설정 */
}
</style>
</html>