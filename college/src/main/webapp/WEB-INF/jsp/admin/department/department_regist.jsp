<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../../sideBar_admin.jsp"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>학과 등록</title>
</head>
<body>
<div class="center">
	<h1>학과 등록하기</h1>
	<form action="/student/department_regist_proc" method='post' id="f">
		<font color="red">${result }</font>
		<table class="table">
			<tr>
				<th>학과명</th>
				<td><input type="text" name="department_Name" id="department_Name"></td>
			</tr>
			<tr>
				<td colspan="2">
					<button class="custom-btn btn-5"
						onclick="allCheck()">
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
<script>
	function allCheck(){
		var department_Name = document.getElementById('department_Name');

		if (department_Name.value == "") {
			alert('학과명을 입력하세요.');
		} else {
			var f = document.getElementById('f');
			f.submit();
		}
	}
</script>
</html>