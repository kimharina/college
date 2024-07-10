<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>학과 세부 정보</title>
</head>
<body>
<div class="center">
	<h1>학과 세부 정보</h1>
	<form action="/student/subject_regist_proc" method='post' id="f">
		<table  class="table">
			<tr>
				<th>학과명</th>
				<td>${department.department_Name }</td>
			</tr>
			<tr>
				<th>학과코드</th>
				<td>${department.department_No }</td>
			</tr>
			<tr>
				<th>학생 총원</th>
				<td>${department.student_Count }</td>
			</tr>
		</table>
		<table class="table">
			<tr>
				<th>학과 교수</th>
			</tr>
			<c:choose>
				<c:when test="${empty professors}">
					<tr>
						<td colspan="1">등록된 교수가 존재하지 않습니다.</td>
					</tr>
				</c:when>
				<c:otherwise>
					<c:forEach var="pro" items="${professors}">
						<tr>
							<td>${pro}</td>
						</tr>
					</c:forEach>
				</c:otherwise>
			</c:choose>
		</table>
	</form>
	<button type="button" class="custom-btn btn-5" onclick="location.href='/student/admin_index'">
		<span>이전으로</span>
	</button>
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

/* 더 나은 레이아웃을 위해 flexbox를 적용합니다. */
#f {
	display: flex;
	flex-direction: column;
	align-items: center;
}

/* 기본 테이블 스타일 */
.table {
	border: 1px;
	border-collapse: collapse;
	width: 40%;
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

/*하단 버튼 css*/
.frame {
	margin: 40px auto;
	text-align: center;}

button {
	margin: 20px;
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
</html>