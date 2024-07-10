<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>학과 정보 수정</title>
</head>
<body>
	<form action="/student/department_update_proc" method="post" id="f">
		<table class="table">
			<tr>
				<th>수정할 학과 입력<input type="hidden" name="department_No"
					id="department_No" value="${department.department_No }"></th>
				<td><input type="text" name="department_New_Name"
					id="department_New_Name"
					placeholder="${department.department_Name }"></td>
			</tr>
			<tr>
				<td colspan="2">
					<button class="custom-btn btn-5" type="submit">
						<span>학과 수정하기</span>
					</button>
					<button type="button" class="custom-btn btn-5"
						onclick="location.href='/student/admin_index'">
						<span>취소하기</span>
					</button>
				</td>
			</tr>
		</table>
	</form>
</body>
<style>
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
	width: 35%;
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
	width: 80%;
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
</style>
</html>