<%@ page language="java" contentType="text/html; charset=UTF-8"  pageEncoding="UTF-8"%>
<%@ include file="../sideBar.jsp" %>
<script src="http://code.jquery.com/jquery-3.6.0.min.js"></script>
<script type="text/javascript">
function allCheck() {
		let name = document.getElementById('name').value;
		let department= document.getElementById('department').value;
		let tel = document.getElementById('tel').value;
		
		if (name == "") {
			alert('이름을 입력하세요.');
			 return false;
		} else if (department == "") {
	        alert('학과를 입력하세요.');
	        return false;
		} else if (tel == "") {
			alert('전화번호를 입력하세요.');
			 return false;
		} else {
			var f = document.getElementById('f');
			f.submit();

		}
	}
$(function(){
	//휴대폰 번호 인증
	
	$("#phoneChk").click(function(){
		var tel = $("#tel").val();
		if(tel == ''){
			alert('휴대폰 번호를 입력해주세요');
		}else{
		    var tel = $("#tel").val();
		    $.ajax({
		        type:"POST",
		        url:"/student/phoneCheck?tel=" + tel,
		        data: {tel:tel},
		        cache : false,
		        success:function(data){
		            if(data == "error"){
		                alert("휴대폰 번호가 올바르지 않습니다.")
		            }else{                    
		                alert("인증번호 발송이 완료되었습니다. 휴대폰에서 인증번호를 확인해주세요.")
		                code2 = data;
		            }
		        } 
		    });
		}
	});
	 
	//휴대폰 인증번호 대조
	$("#cNumChk").click(function(){
		const next = 
		document.getElementById('search');

	      if($("#cNum").val() == code2){
	           alert('인증성공')
	           next.disabled = false;
	           
	      }else{
	          alert('인증실패')
	          next.disabled = true;
	      }
	  });

	});
</script>
<style>
	#search {
	    margin: 0px auto;
	    background-color: #a20131;
	    width: 100px;
	    color: #fff;
	}

	#search:disabled {
	    /* disabled 상태일 때의 스타일 */
	    opacity: 0.5; /* 예시: 투명도를 줄어들게 설정 */
	    color: black;
	    cursor: not-allowed;
	}
</style>
<div id="contents" class="contents">
<ul class="list-icon" style="margin-bottom:10px">
	<li><b>학번 안내</b></li>
</ul>

<div class="form-search">
	<form  action="/student/searchStNum" method="post" id="f">
	<table id="find">
			<colgroup>
				<col width="150px">
				<col width="200px">
				<col>
			</colgroup>			
			<tbody>
				<tr>
					<th>이름</th>
					<td><input type="text" name="name" id="name" size="20" maxlength="10"></td>
				</tr>
				<tr>
					<th>학과</th>
					<td><input type="text" name="department" id="department" size="20" maxlength="10"></td>
				</tr>
				<tr>
					<th>전화번호</th>
					<td>
						<input type="text" name="tel" id="tel" size="20" maxlength="13" placeholder="000-0000-0000">
					</td>
					<td>
						<input type="button" class="btn" value="인증요청" id="phoneChk">
					</td>
				</tr>
				<tr>
					<th>인증번호</th>
					<td>
						<input type="text" name="cNum" id="cNum" size="20" maxlength="13"  placeholder="인증번호 입력">
					</td>
					<td>
						<input type="button" class="btn" value="인증확인" id="cNumChk">
					</td>
				</tr>
				<tr>
					<th></th>					
					<td id="button">
						<input type="button" disabled value="조 회" id="search" onclick="javascript:allCheck()">
					</td>
					<td></td>

				</tr>
		</tbody>
	</table>					
	</form>
</div></div>
</body>
</html>