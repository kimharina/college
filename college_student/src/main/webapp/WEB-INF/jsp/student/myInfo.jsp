<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../sideBar_login.jsp"%>
<style>
	* {
		box-sizing: border-box;
	}
	.name {
		width: 100px;
		font-weight: bold;
	}
	tr{
		height: 40px;
	}

	.save {
		height: 30px;
		width: 100px;
		font-size: 8pt;
		background-color: #a20131;
		color: #fff;
		border-radius: 5px;
		border-width: 1px;
		cursor: pointer;
		}
	#info {
		border: 1px solid #c8c8c8;
		border-radius: 3px;
		background-color: #dcdcdc;
		width: 600px;
		padding: 10px 1px 10px 5px;
		overflow: hidden;
		font-size: 15px;
	}
}
</style>
<div id="contents" class="contents">

<div align="center">
	<h1>내 정보</h1><br>
	<img src="/img/profile.png" alt="Profile Image" width="100" height="100">
		<div id="info">
				<table style="width: 500px;">
					<tr>
						<td colspan="3" ><h3 id="department_Name">${student.department_Name}</h3></td>
					</tr>
					<tr>
						<td id="student_No">${student.student_No}</td>
						<td id="name" style="font-weight: bold;">${student.name }</td>
						<td></td>
					</tr>
	
					<tr>
						<td >전화번호 : </td>
						<td id="tel">${student.tel }</td>
						<td></td>
					</tr>
					<tr>
						<td>이메일 : </td>
						<td id="email">${student.email }</td>
						<td></td>
					</tr>
					<tr>
						<td>생년월일 : </td>
						<td id="birth">${student.birth}</td>
						<td></td>
					</tr>
					<tr>
						<td>주소 : </td>
						<td id="postcode">${postcode}</td>
						<td></td>
					</tr>
					<tr>
						<td></td>
						<td id="address">${address}</td>
						<td></td>
					</tr>
					<tr>
						<td></td>
						<td id="detailAddress">${detailAddress}</td>
						<td></td>
					</tr>
					<tr>
						<td colspan="3" align="center">
							<button type="button" class="save" onclick="location.href='/student/updateInfo'">내정보 수정</button>&nbsp;
							<button type="button" class="save" onclick="location.href='/student/changePw'">비밀번호 변경</button>
							
						</td>
					</tr>
				</table>
		</div>
	</div>
	
</div>
</body>

</html>