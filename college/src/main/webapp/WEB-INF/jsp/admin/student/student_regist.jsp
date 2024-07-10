<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>학생 등록</title>
</head>
<body>
<div class="center">
	<h1>학생 등록하기</h1>
	<form action="/student/student_regist_proc" method="post" id="f">
		<c:if test="${not empty departments }">
			<label>학과 선택</label>
			<select name="department_Name" id="department_Name">
				<c:forEach var="depart" items="${departments }">
					<option value="${depart.department_Name }">${depart.department_Name }</option>
				</c:forEach>
			</select>
			<br>
		</c:if>
		<table class="table">
			<tr>
				<th>학생 이름</th>
				<td><input type="text" name="name" id="name"
					placeholder="학생 이름"></td>
			</tr>
			<tr>
				<th>입학년도(편입년도)</th>
				<td><input type="text" name="years" id="years"
					placeholder="입학년도/편입년도(뒤의 2자리)"></td>
			</tr>
			<tr>
				<td colspan="2"><select name="grade" id="grade">
						<option>== 학년선택 ==</option>
						<option value="1학년">1학년</option>
						<option value="2학년">2학년</option>
						<option value="3학년">3학년</option>
						<option value="4학년">4학년</option>
				</select></td>
			</tr>
			<tr>
				<th>비밀번호</th>
				<td><input type="text" name="password" id="password" placeholder="비밀번호"></td>
			</tr>
			<tr>
				<th>전화번호</th>
				<td><input type="text" name="tel" id="tel" placeholder="전화번호"></td>
			</tr>
			<tr>
				<th>e-mail</th>
				<td><input type="text" name="email" id="email"
					placeholder="e-mail"></td>
			</tr>
			<tr>
				<th>생년월일</th>
				<td><input type="text" name="birth" id="birth"
					placeholder="생년월일"></td>
			</tr>
			<tr>
				<th>주소</th>
				<td><input type="text" name="address" id="address"
					placeholder="주소"></td>
			</tr>
			<tr>
				<td colspan="2">
					<button class="custom-btn btn-5" onclick="allCheck()">
						<span>학생 등록하기</span>
					</button>
					<button class="custom-btn btn-5" type="reset">
						<span>초기화</span>
					</button>
				</td>
			</tr>
		</table>
	</form>
	<br>
	<button type="button" onclick=".href='/student/admin_index'">
		<img src="/img/admin/back.png" alt="뒤로가기"> <span>뒤로가기</span>
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
	width: 63%;
	padding: 8px;
	margin: 3px auto; /* 위아래 여백 추가 */
	box-sizing: border-box;
	text-align: center;
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
<script>
	function allCheck(){
		var department_Name = document.getElementById('department_Name');
		var name = document.getElementById('name');
		var years = document.getElementById('years');
		var grade = document.getElementById('grade');
		var pw = document.getElementById('pw');
		var tel = document.getElementById('tel');
		var birth = document.getElementById('birth');
		var email = document.getElementById('email');
		var address = document.getElementById('address');

		if (department_Name.value == "") {
			alert('학과명을 입력하세요.');
		} else if(name.value == "") {
			alert('이름을 입력하세요.');
		} else if(years.value == "") {
			alert('입학(편입)년도를 입력하세요.');
		} else if(grade.value == "") {
			alert('학년을 입력하세요.');
		} else if(password.value == "") {
			alert('비밀번호를 입력하세요.');
		} else if(tel.value == "") {
			alert('전화번호를 입력하세요.');
		} else if(birth.value == "") {
			alert('생년월일을 입력하세요.');
		} else if(email.value == "") {
			alert('이메일을 입력하세요.');
		} else if(address.value == "") {
			alert('주소를 입력하세요.');
		} else {
			var f = document.getElementById('f');
			f.submit();
		}
	}
</script>
</html>