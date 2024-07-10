<%@ page language="java" contentType="text/html; charset=UTF-8"  pageEncoding="UTF-8"%>
<%@ include file="../sideBar.jsp" %>


<div id="contents" class="contents">
<ul class="list-icon" style="margin-bottom:10px">
	<li><b>학번 안내</b></li>
</ul>

<div class="form-search">

	<table id="find">
		<colgroup>
			<col width="300px">
		</colgroup>			
		<tbody>
		<tr><td>
			${name }님의 학번은 <b>${student_no}</b> 입니다.
		</td></tr>
		<tr><td>
			<input type="button" class="btn-sub" onclick="location.href='/student/login'" value="로그인">
		</td></tr>
		</tbody>
	</table>					
	
</div></div>
</body>
</html>