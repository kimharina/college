



































             		




<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ko" lang="ko">
<head>
   <title>교과목 상세내역</title>
   <meta http-equiv="Content-Type" content="text/html; charset=euc-kr"/>
   <META HTTP-EQUIV="pragma" CONTENT="no-cache"/>
	









<meta name="viewport" content="width=device-width, initial-scale=1.0, target-densitydpi=medium-dpi" />

<meta http-equiv="Cache-Control" content="no-store"/>  
<meta http-equiv="Pragma" content="no-cache"/>  
<meta http-equiv="Expires" content="0"/>  
<link type="text/css" rel="stylesheet" href="/css/new/style.css"  charset="euc-kr" />
<link type="text/css" rel="stylesheet" href="/css/new/sub.css"  charset="euc-kr" />
<link type="text/css" rel="stylesheet" href="/css/new/jquery-ui-1.10.3.custom.css"  charset="euc-kr" />
<!--[if IE 9]>
<link type="text/css" rel="stylesheet" href="/css/new/ie.css" />
<![endif]-->

	











<script type="text/javascript" src="/js/new/jquery-1.10.2.min.js" charset="euc-kr"></script>
<script type="text/javascript" src="/js/new/jquery-ui-1.10.3.custom.min.js" charset="euc-kr"></script>
<script type="text/javascript" src="/js/new/jquery_controller.js" charset="euc-kr"></script>
<!--[if lte IE 8]>
<script type="text/javascript" src="/js/new/PIE.js"></script>
<![endif]-->

<script type="text/javascript">
	document.domain = 'korea.ac.kr';
	var img_src = '/images';
	var css_src = '/css';
	var js_src = '/js';
	var yyyymmdd = '20240103';
	var language = 'ko';
	$(window).load(function(){
		try {
			top.setResize(this);
		} catch(e) {
			
		}
	});
	$(document).ready(function(){
		   $('.close').click(function(){
			   window.close();
			});
	   });
</script>

   <script type="text/javascript">
      function f_list(){    
		location.href='./LecPlan.jsp?year=2023&term=2W&dept_cd=0142&cour_cd=BUSS311&cour_cls=00&cour_nm=&grad_cd=0136&languageDiv=ko';
      }

      function f_print(){
         w_width  = 800;		
         w_height	= 600;		
         w_left	= (screen.width -   parseInt(w_width)) / 2;		
         w_top		= (screen.height -  parseInt(w_height)) / 2;		
         var sURL		  = './LSPPrint.jsp?year=2023&term=2W&gradcd=0136&deptcd=0142&courcd=BUSS311&courcls=00&empno=320739&subempno=&languageDiv=K';		
         
         var sWName	  = "DMPrint";		
         var sWFeature = "status=no,scrollbars=yes,toolbar=no,location=no,directories=no,resizable=yes,menubar=no,overflow=auto," + "width=" + w_width + ",height=" + w_height + ",left=" + w_left + ",top=" + w_top;		window.open(sURL, sWName, sWFeature);
      }

		pgmDown = function(url) {
			window.open(url, '');
		};
		
		 function f_save(){
			 var remark = $('[name=lec_remark]').val().replace(/\n/g, "<br>");
			 var grade = $("[name=lec_grade]:checked").val();
			 if(grade == null ){
				 alert("평가 등급을 선택해주세요.");
				 return false;
			 }
			 if((grade == "04" || grade == "05") && remark == ""){
				 alert("평가 의견을 작성해주세요.");
				 return false;
			 }

			 form = document.form_write;
			 form.target = "hiddenifr" ;
			 form.action = "lecsubjectPlanSave.jsp?year=2023&term=2W&dept_cd=0142&cour_cd=BUSS311&cour_cls=00&cour_nm=&grad_cd=0136&languageDiv=ko&remark="+remark+"&grade="+grade;
			 form.submit();    
			 alert("저장되었습니다."); 
		 }
   </script>
</head>
<body>
	
		<div class="sub_content">
			<div class="top_page">
	  			<h3>2023학년도 계절수업(겨울) [ 조직행동론(영강) ] 강의계획안</h3>
	  			<a href="#" class="close">&nbsp;</a>
			</div>
			<div class="page">
				<form name="form1" method="post" action="lecsubjectPlanSave.jsp">	
					<input type="hidden" name="jobmode" value="" />
					<input type="hidden" name="languageDiv" value="ko" />
					<input type="hidden" name="year" value="2023" />
					<input type="hidden" name="term" value="2W" />
					<input type="hidden" name="dept_cd" value="0142" />
					<input type="hidden" name="cour_cd" value="BUSS311" />
					<input type="hidden" name="grad_cd" value="0136" />
					<input type="hidden" name="cour_cls" value="00" />
					<input type="hidden" name="cour_nm" value="" />
					<input type="hidden" name="col_cd" value="9999" />
				<div class="bottom_btns_right">
					
					
					
					<input type="button" value="목록" " title="목록" class="mbtn btnwhite" onclick="javascript:history.back();"/>
					
					<input type="button" value="출력 " title="출력" class="mbtn btnwhite" onclick="javascript:f_print();"/>
					
				</div>
				<div class="notice_blk">
					<div><p>강의계획안 내용이 없으면, 강의담당 교수님께 문의하시기 바랍니다.</p></div>
				</div>
				<br />
				<span class="tit_redbullet">수업정보</span>
				<table class="tbl_view">
					<colgroup>
						<col width="15%" />
						<col width="35%" />
						<col width="15%" />
						<col width="35%" />
					</colgroup>
					<tbody>
						<tr>
							<th>시간/강의실</th>
							<td colspan="3">월(1-3) 현차관 B206호
화(1-3) 현차관 B206호
수(1-3) 현차관 B206호
목(1-3) 현차관 B206호</td>
						</tr>
						<tr>
							<th>학점</th>
							<td>3</td>
							<th>학수번호(분반)</th>
							<td>BUSS311 ( 00 )</td>
						</tr>
						
							<tr>
								<th>이수구분</th>
								<td>전공필수</td>
								<th>설계비중</th>
								<td>%</td>
							</tr>
											
					</tbody>
				</table>
				
				<span class="tit_redbullet">강의담당자 </span>
				<div class="bottom_view">
					<span class="photo">
						
						<img src="lecEmpPhoto.jsp?languageDiv=ko&Id=320739" alt="담당교수사진" border=0 width="156" height="189"/>
							
						<div style="text-align:center; font-weight:bold;padding-top:5px;">담당교수</div>
					</span>
					<table class="tbl_view">
						<colgroup>
							<col width="15%" />
							<col width="25%" />
							<col width="15%" />
							<col width="" />
						</colgroup>
						<tbody>
							<tr>
								<th>성명</th>
								<td>오주연</td>
								<th>소속</th>
								<td>경영학과</td>
							</tr>
							<tr>
								<th>E-mail</th>
								<td>diozones@korea.ac.kr</td>
								<th>Homepage</th>
								<td></td>
							</tr>
							<tr>
								<th>연구실호실</th>
								<td></td>
								<th>연락처</th>
								<td></td>
							</tr>
							<tr>
								<th>면담시간</th>
								<td colspan="3"></td>
							</tr>
						</tbody>
					</table>
				</div>
				
				<span class="tit_redbullet">조교정보 </span>
				<table class="tbl_view">
					<colgroup>
						<col width="15%" />
						<col width="25%" />
						<col width="15%" />
						<col width="" />
					</colgroup>
					<tbody>
						<tr>
							<th>성명</th>
							<td></td>
							<th>소속</th>
							<td></td>
						</tr>
						<tr>
							<th>E-mail</th>
							<td colspan="3"></td>
						</tr>
						<tr>
							<th>연구실</th>
							<td></td>
							<th>연락처</th>
							<td></td>
						</tr>
					</tbody>
				</table>
				<br />
				<h3>수업운영</h3>
				<span class="tit_redbullet">수업방법 </span>
				<table class="tbl_view">
					<colgroup>
						<col width="17%" />
						<col width="16%" />
						<col width="16%" />
						<col width="16%" />
						<col width="16%" />
						<col width="16%" />
					</colgroup>
					<tbody>
						<tr>
							<th><b>수업유형</b></th>
							<td><label class="invisible" for="class_type_m">대면</label><input type="radio" value="01" name="CLASS_TYPE" id="class_type_m" checked disabled /> 대면</td>
							<td><label class="invisible" for="class_type_n">비대면</label><input type="radio" value="02" name="CLASS_TYPE" id="class_type_n"  disabled /> 비대면</td>
							<td colspan="3">
								<label class="invisible" for="class_type_x">병행(대면&비대면 동시)</label><input type="radio" value="03" name="CLASS_TYPE"  id="class_type_x"  disabled /> 병행(대면&비대면 동시)
							</td>
							<!-- td><input type="radio" value="" name="CLASS_TYPE"  disabled> 미정</td-->
						</tr>
						
						<tr>
							<th rowspan="2">활동유형</th>
							<td><label class="invisible" for="containsKey0">강의</label><input type="checkbox" id="containsKey0" value="0" checked disabled />강의</td>
							<td><label class="invisible" for="containsKey1">발표</label><input type="checkbox" id="containsKey1" value="1"  disabled />발표</td>
							<td><label class="invisible" for="containsKey2">토론</label><input type="checkbox" id="containsKey2" value="2"  disabled />토론</td>
							<td><label class="invisible" for="containsKey3">실험</label><input type="checkbox" id="containsKey3" value="3"  disabled />실험</td>
							<td><label class="invisible" for="containsKey4">실습</label><input type="checkbox" id="containsKey4" value="4"  disabled />실습</td>
						</tr>
						<tr class="wborder">
							<td><label class="invisible" for="containsKey5">협동학습</label><input type="checkbox" id="containsKey5" value="5"  disabled />협동학습</td>
							<td><label class="invisible" for="containsKey6">개별지도</label><input type="checkbox" id="containsKey6" value="6"  disabled />개별지도</td>
							<td><label class="invisible" for="containsKey7">집단지도</label><input type="checkbox" id="containsKey7" value="7"  disabled />집단지도</td>
							<td><label class="invisible" for="containsKey8">퀴즈</label><input type="checkbox" id="containsKey8" value="8"  disabled />퀴즈</td>
							<td><label class="invisible" for="containsKey9">Q&A</label><input type="checkbox" id="containsKey9" value="9"  disabled />Q&A</td>
						</tr>
						<tr>
							<th><b>출석확인자율화</b></th>
							<td colspan="5">
								<label class="invisible" for="attend_free_y">예</label><input type="radio" value="Y" name="ATTEND_FREE_YN" id="attend_free_y"  disabled /> 예&nbsp;&nbsp;
								<label class="invisible" for="attend_free_n">아니오</label><input type="radio" value="N" name="ATTEND_FREE_YN" id="attend_free_n" checked disabled /> 아니오
							</td>
						</tr>
						<tr>	
							<th><b>무감독시험</b></th>
							<td colspan="5">
								<label class="invisible" for="no_supervisor_y">예</label><input type="radio" value="Y" name="NO_SUPERVISOR_YN" id="no_supervisor_y"  disabled /> 예&nbsp;&nbsp;
								<label class="invisible" for="no_supervisor_n">아니오</label><input type="radio" value="N" name="NO_SUPERVISOR_YN" id="no_supervisor_n" checked disabled /> 아니오
							</td>
						</tr>
						
					</tbody>
				</table>
				
				<span class="tit_redbullet">평가방법</span>
				<table class="tbl_view">
					<colgroup>
						<col width="25%" />
						<col width="75%" />
					</colgroup>
					<tbody>
						
						<tr>
							<td colspan="4">평가방법이 입력 되지 않았습니다</td>
						</tr>
						
						 <tr>
						 	<th>평가점수 공개여부</th>
						 	<td colspan="3">비공개</td>
						 </tr>
						 
					</tbody>
				</table>
				<br/>
				
				<span class="tit_redbullet">핵심역량</span>
				<table>
						<tbody>
					<tr>
						<th>공감</th>
						<th>의사소통</th>
						<th>윤리</th>
						<th>사회공헌</th>
						<th>전문가</th>
						<th>통합</th>
						<th>창의</th>
						<th>문제해결</th>
						<th>다문화</th>
						<th>갈등통합</th>
						<th>자기실현</th>
						<th>변화주도</th>
					</tr>
					<tr>
						<td>10</td>
						<td>15</td>
						<td>10</td>
						<td>5</td>
						<td>5</td>
						<td>10</td>
						<td>10</td>
						<td>10</td>
						<td>5</td>
						<td>5</td>
						<td>5</td>
						<td>10</td>
					</tr>
				</tbody>
				</table>
				<br/>
				
				
				<span class="tit_redbullet">공학교육인증 평가항목 설정</span>
				<table>
						<colgroup>
							<col width="25%" />
							<col width="75%" />
						</colgroup>
						<tbody>
							<tr>
								<th>ABEEK 평가항목</th>
								<td>관련도</td>
							</tr>
							<tr>
								<th>강의내용</th>
								<td>평가방법</td>
							</tr>
				
							
					</tbody>
				</table>
						
				
				<span class="tit_redbullet">학습계획</span>
		
						
				<table class="tbl_view">
					<colspan>
						<col width="20%" />
						<col width="" />
					</colspan>
					<tbody>	
						<tr>
							<td colspan="2" class="aleft">
								
								▶ 첨부파일
								<br />&nbsp;&nbsp;* 첨부파일이 직접 열리지 않는 경우는 로컬PC에 [저장]하신 후 열어보시기 바랍니다.
	 							<br />&nbsp;&nbsp;* 첨부파일이 직접 열리도록 하려면 [제어판]->[폴더옵션]->[파일형식]에서 해당파일 확장자를 등록하고
	 							<br />&nbsp;&nbsp;&nbsp;&nbsp;연결프로그램을 등록하십시오.
								<br />&nbsp;&nbsp;* PC에 설치되어 있는 프로그램보다 상위버전에서 작성된 파일인 경우 열리지 않을 수 있습니다.
								
							</td>
						</tr>	
				
						<tr>
							<td>
								<img src="./images/f_addfile.gif" alt="첨부문서" border="0" />
							</td>
							<td  style="border:none">
								 <a href="/weblogic/filedownloader?filename=BUSS311%2800%29.pdf&filepath=%2Fsrc%2Fintr%2Fwebapp%2Ffiles%2Flec%2F20232W%2FBUSS311%2800%29.pdf">
									<span class="title01">강의계획서 첨부문서</span>
								</a>
							</td>
						</tr>
				
					</tbody>
				</table>
				<br />
				<span class="tit_redbullet">지정도서 및 참고문헌</span>
				<iframe name="myiframe3" src='./lecsubjectRefBook.jsp?year=2023&term=2W&dept_cd=0142&grad_cd=0136&languageDiv=ko&cour_cd=BUSS311&cour_cls=00&empno=320739' frameborder="0" border="0" style="width:100%; height:120px;"></iframe>
				<br />	
				<span class="tit_redbullet"> 기타 (설계관련사항포함 2000자) </span>
				<table class="tbl_view">
					<colgroup>
						<col width="100%" />
					</colgroup>
					<tbody>
						<tr>
							<td><br /><br /></td>
						</tr>
					</tbody>
				</table>
				
				
				<span class="tit_redbullet">설계계획</span>
		
				<table class="tbl_view">
					<colspan>
						<col width="20%" />
						<col width="" />
					</colspan>
					<tbody>	
						<tr>
							<td colspan="2" class="aleft">▶ 첨부파일
								<br />&nbsp;&nbsp;* 첨부파일이 직접 열리지 않는 경우는 로컬PC에 [저장]하신 후 열어보시기 바랍니다.
	 							<br />&nbsp;&nbsp;* 첨부파일이 직접 열리도록 하려면 [제어판]->[폴더옵션]->[파일형식]에서 해당파일 확장자를 등록하고
	 							<br />&nbsp;&nbsp;&nbsp;&nbsp;연결프로그램을 등록하십시오.
								<br />&nbsp;&nbsp;* PC에 설치되어 있는 프로그램보다 상위버전에서 작성된 파일인 경우 열리지 않을 수 있습니다.
							</td>
						</tr>	
				
						<tr>
							<td colspan="2">
								<span>첨부된 파일이 존재하지 않습니다.</span>
							</td>
						</tr>
				
					</tbody>
				</table>
				
				</form>
				<span class="tit_redbullet">장애학생조정사항</span>
				<table class="tbl_view">
					<tbody>
						<tr>
							<td>장애학생은 강의 수강 시 조정(강의자료 사전 제공, 과제 및 평가 조정, 과제 제출기간 연장, 시험시간 연장 등)을 원할 경우 개강 전 담당 교수님께 위와 같은 사항에 대한 사전 상담을 요청해 주시기 바랍니다.<br/>- 교원 가이드북 : <a href="http://ibook.korea.ac.kr/Viewer/kuprofessors" target="_blank">http://ibook.korea.ac.kr/Viewer/kuprofessors</a></td>
						</tr>
					</tbody>
				</table>
				<form name="form_write" method="post" action="lecsubjectPlanSave.jsp">
					
			</form>
			</div>
		</div>
	</div>
</div>

<iframe id="hidden" name="hiddenifr"style="visibility:hidden;display:none"></iframe>
</body>
</html>
