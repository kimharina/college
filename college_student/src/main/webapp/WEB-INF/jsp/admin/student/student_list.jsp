<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>학생 목록</title>
<script>
	function deleteCheck(student_No) {
		result = confirm('삭제하겠습니까?');
		if (result == true) {
			location.href = '/student/student_delete?student_No=' + student_No
		}
	}
</script>
</head>
<body>
	<c:choose>
		<c:when test="${empty students }">
			<h1>등록된 학생이 존재하지 않습니다.</h1>
			<button type="button" onclick="location.href='/student/student_regist'">학생등록</button>
			<button type="button" onclick="location.href='/student/admin_index'">이전으로
				가기</button>
		</c:when>
		<c:otherwise>

			<table class="table">
				<tr>
					<th>학번</th>
					<th>이름</th>
					<th>학과명</th>
					<th>학년</th>
					<th>정보 보기</th>
					<th>삭제</th>
				</tr>

				<c:forEach var="stu" items="${students}">
					<tr>
						<td>${stu.student_No}</td>
						<td>${stu.name}</td>
						<td>${stu.department_Name}</td>
						<td>${stu.grade}</td>
						<td>
							<div class="button">
								<p class="btnText">세부 정보</p>
								<div class="btnTwo"
									onclick="location.href='/student/student_info?student_No=${stu.student_No}'">
									<p class="btnText2">GO!</p>
								</div>
							</div>
						</td>
						<td>
							<div class="button">
								<p class="btnText">학생 삭제</p>
								<div class="btnTwo" onclick="deleteCheck('${stu.student_No}')">
									<p class="btnText2">X</p>
								</div>
							</div>
						</td>
					</tr>
				</c:forEach>
			</table>
			<button class="custom-btn btn-5"
				onclick="location.href='/student/student_regist'">
				<span>학생등록</span>
			</button>
			<button class="custom-btn btn-5"
				onclick="location.href='/student/admin_index'">
				<span>이전으로 가기</span>
			</button>
		</c:otherwise>
	</c:choose>
</body>
<style>
/* 테이블 스타일 */
.table {
	border: 1;
	border-collapse: collapse;
	width: 100%;
	border: 1px solid #333; /* 바깥 테두리를 진한 회색으로 지정 */
	box-shadow: 5px 5px 10px #888888; /* 그림자 추가 */
	margin-bottom: 7px;
}

/* 테이블 헤더 스타일 */
th {
	padding: 10px;
	text-align: center; /* 가운데 정렬 */
	background-color: #f2f2f2;
}

/* 테이블 데이터 셀 스타일 */
td {
	padding: 0px;
	text-align: center; /* 가운데 정렬 */
}

/* 테이블 내에서 셀의 선을 없애기 위한 스타일 */
td, th {
	border: none;
}

/*학과 수정/삭제 버튼*/
.button {
	background: #887673;
	margin: 10px auto;
	width: 120px; /* 조정한 부분 */
	height: 38px; /* 조정한 부분 */
	overflow: hidden;
	text-align: center;
	transition: .2s;
	cursor: pointer;
	border-radius: 3px;
	box-shadow: 0px 1px 2px rgba(0, 0, 0, .2);
	position: relative;
	color: white;
}

.btnTwo {
	position: absolute;
	width: 45%;
	height: 100%;
	background: #300c09;
	left: -80%;
	transition: .3s;
	display: flex;
	align-items: top;
	justify-content: flex-end;
}

.btnText {
	color: #FFF;
}

.btnText2 {
	margin-left: auto;
	margin-right: 20px;
	color: #FFF;
}

.button:hover .btnTwo {
	left: 0;
}

.button:hover .btnText {
	margin-left: 65px;
}

.button:active {
	box-shadow: 0px 5px 6px rgba(0, 0, 0, 0.3);
}

/*하단 버튼 2개 css*/
.frame {
	width: 90%;
	margin: 40px auto;
	text-align: center;
}

button {
	margin: 20px;
	outline: none;
}

.custom-btn {
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
</html>