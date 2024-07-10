<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html lang="ko">
<head>
<link rel="shortcut icon" href="/img/favicon.png">
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="format-detection" content="telephone=no" />
<meta property="og:url" content="https://oku.korea.ac.kr/oku/index.do" />
<meta property="og:title" content="인재발굴처" />
<meta property="og:description" content="메인" />
<meta property="og:type" content="website" />
<meta property="og:site_name" content="인재발굴처"/>
<meta property="og:image" content="https://oku.korea.ac.kr/img/bvs/snslogo.jpg" />
<title>인재발굴처 메인</title>


<link rel="stylesheet" type="text/css" href="/kru/css/common.css" /><!-- reset -->
<link rel="stylesheet" type="text/css" href="/kru/css/board.css" /><!-- board -->
<link rel="stylesheet" type="text/css" href="/kru/type/IPSI_A/css/layout.css" /><!-- 개별 -->
<link rel="stylesheet" type="text/css" href="/kru/type/IPSI_A/css/main.css" /><!-- main -->

<link rel="stylesheet" href="/kru/css/pop_zone.css" />
<link rel="stylesheet" href="/css/jquery-ui.css" />
<link rel="stylesheet" href="/css/jquery-ui.theme.css" />

<script type="text/javascript" src="/js/jquery-2.2.1.min.js"></script>
<script type="text/javascript" src="/js/jquery.font-accessibility.dev.js"></script>

<!-- slick -->
<link rel="stylesheet" type="text/css" href="/kru/js/slick/slick.css" />
<script type="text/javascript" src="/kru/js/slick/slick.min.js"></script>
<script type="text/javascript" src="/kru/js/slick/slick.acc.js"></script>

<!-- mCustomScrollbar -->
<link rel="stylesheet" type="text/css" href="/kru/js/mCustomScrollbar/jquery.mCustomScrollbar.css" />
<script type="text/javascript" src="/kru/js/mCustomScrollbar/jquery.mCustomScrollbar.concat.min.js"></script>

<script type="text/javascript" src="/kru/js/common.js"></script><!-- 공통 스크립트 -->
<script type="text/javascript" src="/kru/type/IPSI_A/js/layout.js"></script><!-- layout -->
<script type="text/javascript" src="/kru/type/IPSI_A/js/main.js"></script><!-- main -->

<script src="/js/jquery.form.js"></script>
<script src="/js/jquery-ui.min.js"></script>
<script src="/js/comm_fr.js"></script>
<script src="/js/util.js"></script>
<script src="/js/jquery.tmpl.js"></script><!-- tcontrol -->
<script type="text/javascript" src="/js/tcontrolx.js" charset="utf-8"></script>
<!-- tcontrol -->
<script>
var date = new Date();

$().ready(function() {

    
	    if(getCookie("a_headTop_bnr") == "done"){
	        $("#header").removeAttr('style');
			$("body").removeClass('typeHeadBnr');
	        $("div#headTop_bnr").remove();
	    }else{
			$("body").addClass('typeHeadBnr');

	    }
    

	/* slick 1개 이하에서 페이징 미노출 */
	$(".slick-dots").each(function(){
		if($(this).children('li').length < 2){
			$(this).hide();
		}
	});

	$(document).on("click",".bbs_grp .btn_more", function(){
		var obj = $(".bbs_tab").find("li a.on");
        location.href = "/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE="+$(obj).data("tc")+"&BASE_SITE_NO="+$(obj).data("bsn")+"&CONFIG_CD="+$(obj).data("cc")+"&CONFIG_SEQ="+$(obj).data("cs")+"&SUB_SEQ="+$(obj).data("ss");
	});

	$(".movie_area dd").html("<p>"+removeTag($(".movie_area dd").html())+"</p>");


	$(document).on("click", ".calendarM .btnm", function(){
		if($(this).data("move") == "prev"){
			date.setMonth(date.getMonth()-1,1);
		   	fn_calendar(date);
		   	return false;
		}else{
			date.setMonth(date.getMonth()+1,1);
		  	fn_calendar(date);
		  	return false;
		}
	});
});

function closePop(obj){
    if($(obj).prop("checked")){
        setCookie($(obj).parents("div.pop").attr("id"),"done",1);
    }
    $(obj).parents("div.pop").remove();
}

function removeTag( html ) {
	if( html == null || typeof html == 'undefined') return '';
	else return html.replace(/(<([^>]+)>)/gi, "");
}
function fn_calendar(date){
	var year = date.getFullYear();
	var month = "";
	if ( String(date.getMonth()+1).length <= 1 ) {
		month = "0" + (date.getMonth()+1);
	} else {
		month = (date.getMonth()+1);
	}
	$("#move_calendar").text(year+"."+month);
	draw_calendar(year, month);
}
function draw_calendar(year, month){
	fn_comm_ajax({
		url : "/oku/ajaxf/FR_MAIN_SVC/MainSchData.do",
		data : $("#schFrm").serialize()+"&YEAR="+year+"&MONTH="+month, //{YEAR : year, MONTH : month},
		dataType : "json",
		success : function(data) {
// 			$(".calendarD").empty();
			var sch_Month_Info = '';
			if(data.data0.length >0){
				for(var i=0; i<data.data0.length; i++){
					sch_Month_Info += '<li class="'+data.data0[i].DAY_NM+'" >'+data.data0[i].DAY_INFO+'</li>';
				}
				$(".calendarD").html($(sch_Month_Info));
			}
			if(data.data1.length > 0){
				$(".no_scheduleList").hide();
				$(".scheduleList").remove();
				var sch_Items = '<div class="scheduleList">';
				for(var j=0; j<data.data1.length; j++){
					sch_Items += '<div class="unit">';

					sch_Items += '<a href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO='+data.data1[j].SITE_NO+'&BASE_MENU_NO='+data.data1[j].BOARD_CD+'" target="_self" data-check="'+data.data1[j].CHK+'">';
					sch_Items += '   <span class="dateY">'+data.data1[j].START_Y+'</span>';
					sch_Items += '   <span class="dateMD">';
					if(data.data1[j].START_DAY == data.data1[j].END_DAY){
						sch_Items += data.data1[j].START_M+"."+data.data1[j].START_D+"("+data.data1[j].START_YOIL+")";
					} else if(data.data1[j].START_M == data.data1[j].END_M) {
						sch_Items += data.data1[j].START_M+"."+data.data1[j].START_D+"("+data.data1[j].START_YOIL+") ~ "+data.data1[j].END_D+"("+data.data1[j].END_YOIL+")";
					} else {
						sch_Items += data.data1[j].START_M+"."+data.data1[j].START_D+"("+data.data1[j].START_YOIL+") ~ "+data.data1[j].END_M+"."+data.data1[j].END_D+"("+data.data1[j].END_YOIL+")";
					}
					sch_Items += '   </span>';
					sch_Items += '  <p>'+data.data1[j].SUBJECT+'</p>';
					sch_Items += '</a>';
					sch_Items += '</div>';
				}
				sch_Items += '</div>';
				$(sch_Items).appendTo($(".mSchedule"));
				setSlick();
			}else{
				$(".no_scheduleList").show();
				$(".scheduleList").remove();
			}
		}
	});
}

function setSlick(){
	$('.mSchedule .scheduleList').slick({
		infinite: false,
		arrows: true,
		dots: false,
		slidesToShow: 4,
		slidesToScroll: 4,
		responsive: [
			{
				breakpoint: 1041,
				settings: {
					slidesToShow: 3,
					slidesToScroll: 1
				}
			},
			{
				breakpoint: 768,
				settings: {
					arrows: false,
					slidesToShow: 1,
					slidesToScroll: 1,
					variableWidth: true
				}
			}
		]
	});

	//$('.mSchedule .scheduleList').slick("slickGoTo", 0 );

	$('.mSchedule .scheduleList .slick-prev').text("이전일정");
	$('.mSchedule .scheduleList .slick-next').text("다음일정");
	ScheduleGoDay();

}

function ScheduleGoDay(){
	var check =0;
	$('.mSchedule .slick-track a').each(function() {
        thisVal = $(this).data('check');
        var $this = $(this);
        if(thisVal == 'CK') {
        	check = $(this).parent('div').data('slick-index');
        }
    });

	if($('.mSchedule .scheduleList').slick("slickGetOption","slidesToShow")== 3){
		check = (check+1)-3;
	}
	$('.mSchedule .scheduleList').slick("slickGoTo", check);
}

window.onload = function () {
	 
		if(getCookie("a_pop_zone") != "done"){
			$("header .util .btn_topPopzone").click();
	   	}else{
	   		$(".popZone input:checkbox").prop("checked",true);
	   	}
	

	ScheduleGoDay();
}
</script>
</head>
<body class="typeMain">
    


<div class="popZone">
    <div class="popZone_wrap">
        <div class="list">
        	
        		<a href="https://ratio.uwayapply.com/Sl5KOGB9YTlKOmJpSnpmVGY=" target="_blank"><img src="/ajaxfile/CMN_SVC/FileView.do?GBN=X15&POPUP_SEQ=344&SITE_NO=2" alt="2024학년도 편입학
최종
경쟁률
[ 바로가기 ]" /></a>
        	
        		<a href="https://oku.korea.ac.kr/oku/cms/FR_BBS_CON/BoardView.do?pageNo=1&pagePerCnt=10&MENU_ID=750&CONTENTS_NO=&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1592&PWD=&CATE_SEQ=&SEARCH_FLD=&SEARCH=" target="_self"><img src="/ajaxfile/CMN_SVC/FileView.do?GBN=X15&POPUP_SEQ=343&SITE_NO=2" alt="2023년 KU 전공체험강의실(KU Lecture)참가 안내" /></a>
        	  
        </div>
		<div class="btn">
			<span class="limit">  
				<span  class="inp_redCheck">
					<input type="checkbox" name="openLimit_popzone" id="openLimit_popzone"  data-seq="pop_zone" onclick="closeTopBanner(this);"/>
					<label for="openLimit_popzone">하루동안 열지않기</label>
				</span>
			</span>
			<button class="btn_popZone_close">닫기</button>
		</div>
    </div>
</div>

<div id="skip_menu">
	<a href="#contents" title="본문 바로가기">본문 바로가기</a>
	<a href="#header" title="주메뉴 바로가기">주메뉴 바로가기</a>
	<a href="#footer" title="푸터 바로가기">푸터 바로가기</a>
</div>
<div id="dim"></div>
	<div id="pop_dim" style="z-index: 2000;"></div>
	<div id="headTop_bnr">
			<div class="bnr_area">
				<div class="list">
					<div class="bnr">
							<a href="https://oku.korea.ac.kr/oku/cms/FR_BBS_CON/BoardView.do?MENU_ID=750&CONTENTS_NO=&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1216" target="_self" >
								<img src="/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1430&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=10" alt="고등학교 교사용 고교별 합격자 조회 서비스 사용 안내" />
							</a>
						</div>
					</div>
				<div class="btn">
					<span class="limit">
						<span  class="inp_redCheck">
						<input type="checkbox" name="openLimit" id="openLimit" data-seq="top_bnr" onclick="closeTopBanner(this);"/>
						<label for="openLimit">하루동안 열지않기</label></span>
					</span>
					<button class="btn_close">닫기</button>
				</div>
			</div>
		</div>
	



<script>
function setHref(obj, org){

		if($(obj).find("> div").length > 0){
			if($(obj).find("> div> ul > li").length > 0){
				if($(obj).find(">a").data("sub")=="Y"){
					$(org).find(">a").attr("href",$(obj).find("> div> ul > li:eq(0) > a").attr("href"));
					$(org).find(">a").attr("target",$(obj).find("> div> ul > li:eq(0) > a").attr("target"));
				}else{
					$(org).find(">a").attr("href",$(org).find(">a").attr("href"));
				}
				setHref($(obj).find("> div> ul > li:eq(0)"),org);
			}
		}else{
			if($(obj).find("> ul > li").length > 0){
				if($(obj).find(">a").data("sub")=="Y"){
					$(org).find(">a").attr("href",$(obj).find("> ul > li:eq(0) > a").attr("href"));
					$(org).find(">a").attr("target",$(obj).find("> ul > li:eq(0) > a").attr("target"));
				}else{
					$(org).find(">a").attr("href",$(org).find(">a").attr("href"));
				}
				setHref($(obj).find("> ul > li:eq(0)"),org);
			}
		}
}


function setSnbHref(obj, org){
	var v_menuno = ($(obj).data("menuno"));
	var v_sub = ($(obj).data("sub"));

	if($("ul#gnb li."+v_menuno+" > .menuM").length > 0){
		if($("ul#gnb li."+v_menuno+" > .menuM > li").length > 0){
			if(v_sub=="Y"){
				$(org).attr("href",$("ul#gnb li."+v_menuno+" > .menuM > li:eq(0) > a").attr("href"));
				$(org).attr("target",$("ul#gnb li."+v_menuno+" > .menuM > li:eq(0) > a").attr("target"));
			}else{
				$(org).attr("href",$(org).find(">a").attr("href"));
			}
			setHref($("ul#gnb li."+v_menuno+" >  div > ul > li:eq(0)"),org);
		}
	}else{
		if($("ul#gnb li."+v_menuno+" > ul > li").length > 0){
			if(v_sub=="Y"){
				$(org).find(">a").attr("href",$("ul#gnb li."+v_menuno+" > ul > li:eq(0) > a").attr("href"));
				$(org).find(">a").attr("target",$("ul#gnb li."+v_menuno+" > ul > li:eq(0) > a").attr("target"));
			}else{
				$(org).find(">a").attr("href",$(org).find(">a").attr("href"));
			}
			setHref($("ul#gnb li."+v_menuno+" > ul > li:eq(0)"),org);
		}
	}
}

function setParentHref(obj){
	if($("ul#gnb > li."+$(obj).find(">a").data("menuno")+"> ul.menuM > li").length > 0){
		if($(obj).find(">a").data("sub")=="Y"){
			$(obj).find(">a").attr("href",$("."+$(obj).find(">a").data("menuno")+"> .menuM > li:eq(0) > a").attr("href"));
			$(obj).find(">a").attr("target",$("."+$(obj).find(">a").data("menuno")+"> .menuM > li:eq(0) > a").attr("target"));
		}
	}
}

$(function(){
	$(document).on("click", "ul#gnb li, ul#rnb li:not(ul#rnb>li.child), .mSnb_menu li", function(){
		setHref($(this),$(this));
	});
	$(document).on("click", "ul#gnb_parent li", function(){
		setParentHref($(this));
	});
	
	$(document).on("click", "nav#snb_nav .snb_area li a", function(){
		setSnbHref($(this),$(this));
	});
	
	$(document).on("click", ".btn_topSearch", function(){
		ifrTotalSearchPop('SearchPop','/oku/cms/FR_CON/SearchPop.do');
	});
	$(document).on("click", ".btn_topSitemap", function(){
		ifrSiteMapPop('SitePop','/oku/cms/FR_CON/SiteMapPop.do?SGN=2&SN=2');
	});
	
	
	if(getCookie("a_pop_zone") == "done"){
		$(".popZone input:checkbox").prop("checked",true);
	 }
	
	$(".popZone").hide();
});

function closeTopBanner(obj){
	if($(obj).data('seq')=='top_bnr'){
		$("#headTop_bnr .btn>.btn_close").click(function(){
			if($(obj).prop("checked")){
				setCookie("a_headTop_bnr","done",1);
			} 
		});
		
	}else if($(obj).data('seq') == 'pop_zone'){
		$(".popZone .btn .btn_popZone_close").click(function(){
			if($(obj).prop("checked")){
				setCookie("a_pop_zone","done",1);
				
			}else{
				fn_util_removeCookie("a_pop_zone");
			}
		});
	}
}
</script>
<div id="header">
	<h1 class="logo">
		
			<a href="https://oku.korea.ac.kr/oku/index.do">인재발굴처</a>
	</h1>
	<header>
		<ul class="siteCateg">
			<li><a href="/student/index" target="_blank" title="새창">카리나대학교</a></li>
		</ul>
		<button type="button" class="mBtn_topMenu">MENU</button>
		<div id="gnb_dim"></div>
		
		<nav>
			<ul id="gnb_parent">
				
					<li>
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=550" title="모집요강 현재창  이동" data-menuno="550" data-sub="Y" target="_self"><span>모집요강</span></a>
					</li>
				
					<li>
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=570" title="입학자료실 현재창  이동" data-menuno="570" data-sub="Y" target="_self"><span>입학자료실</span></a>
					</li>
				
					<li>
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=580" title="입학도우미 현재창  이동" data-menuno="580" data-sub="Y" target="_self"><span>입학도우미</span></a>
					</li>
				
					<li>
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=590" title="진로진학상담센터 현재창  이동" data-menuno="590" data-sub="Y" target="_self"><span>진로진학상담센터</span></a>
					</li>
				
					<li>
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=600" title="학교안내 현재창  이동" data-menuno="600" data-sub="Y" target="_self"><span>학교안내</span></a>
					</li>
				
	        </ul>
	        
			<ul id="gnb">
	            
		           	<li class="point 550" >
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=550" title="모집요강 현재창  이동" data-sub="Y" target="_self" ><span>모집요강</span></a>
							
				           		<ul class="menuM">
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=680" title="수시모집 현재창  이동" data-sub="Y" target="_self">수시모집</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=650" title="정시모집 현재창  이동" data-sub="Y" target="_self">정시모집</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=660" title="편입학 현재창  이동" data-sub="Y" target="_self">편입학</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=690" title="특별전형(전기) 현재창  이동" data-sub="Y" target="_self">특별전형(전기)</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=1370" title="특별전형(후기) 현재창  이동" data-sub="Y" target="_self">특별전형(후기)</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=700" title="International Students 현재창  이동" data-sub="Y" target="_self">International Students</a>
						           		</li>
					           		
								</ul>
							
		           	</li>
           	 	
		           	<li class="point 570" >
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=570" title="입학자료실 현재창  이동" data-sub="Y" target="_self" ><span>입학자료실</span></a>
							
				           		<ul class="menuM">
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=710" title="지원율통계 현재창  이동" data-sub="Y" target="_self">지원율통계</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=720" title="기출문제 현재창  이동" data-sub="Y" target="_self">기출문제</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=730" title="제출서류 현재창  이동" data-sub="Y" target="_self">제출서류</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=740" title="전년도 모집요강 현재창  이동" data-sub="Y" target="_self">전년도 모집요강</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=1400" title="인재발굴처 규정 현재창  이동" data-sub="Y" target="_self">인재발굴처 규정</a>
						           		</li>
					           		
								</ul>
							
		           	</li>
           	 	
		           	<li class="point 580" >
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=580" title="입학도우미 현재창  이동" data-sub="Y" target="_self" ><span>입학도우미</span></a>
							
				           		<ul class="menuM">
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=750" title="공지사항 현재창  이동" data-sub="Y" target="_self">공지사항</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=1060" title="통합일정 현재창  이동" data-sub="Y" target="_self">통합일정</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=760" title="입학설명회/면접영상 현재창  이동" data-sub="Y" target="_self">입학설명회/면접영상</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=770" title="입학정보자료 현재창  이동" data-sub="Y" target="_self">입학정보자료</a>
						           		</li>
					           		
								</ul>
							
		           	</li>
           	 	
		           	<li class="point 590" >
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=590" title="진로진학상담센터 현재창  이동" data-sub="Y" target="_self" ><span>진로진학상담센터</span></a>
							
				           		<ul class="menuM">
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=790" title="FAQ 현재창  이동" data-sub="Y" target="_self">FAQ</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=1540" title="Q&A 현재창  이동" data-sub="Y" target="_self">Q&A</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=810" title="동영상 강의 현재창  이동" data-sub="Y" target="_self">동영상 강의</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=1380" title="학과소개영상 현재창  이동" data-sub="Y" target="_self">학과소개영상</a>
						           		</li>
					           		
								</ul>
							
		           	</li>
           	 	
		           	<li class="point 600" >
						<a href="/oku/cms/FR_CON/index.do?MENU_ID=600" title="학교안내 현재창  이동" data-sub="Y" target="_self" ><span>학교안내</span></a>
							
				           		<ul class="menuM">
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=820" title="전공안내 현재창  이동" data-sub="Y" target="_self">전공안내</a>
						           		</li>
					           		
						           		<li>
						           			<a href="https://registrar.korea.ac.kr/eduinfo/info/major_double.do" title="다양한 전공제도  새창 이동" data-sub="N" target="_blank">다양한 전공제도</a>
						           		</li>
					           		
						           		<li>
						           			<a href="https://dorm.korea.ac.kr/front/main" title="기숙사  새창 이동" data-sub="N" target="_blank">기숙사</a>
						           		</li>
					           		
						           		<li>
						           			<a href="https://tour.korea.ac.kr/tour/index.do" title="견학프로그램  새창 이동" data-sub="N" target="_blank">견학프로그램</a>
						           		</li>
					           		
						           		<li>
						           			<a href="http://www.korea.ac.kr/mbshome/mbs/university/subview5.jsp?id=university_010501000000" title="캠퍼스맵  새창 이동" data-sub="N" target="_blank">캠퍼스맵</a>
						           		</li>
					           		
						           		<li>
						           			<a href="/oku/cms/FR_CON/index.do?MENU_ID=880" title="인재발굴처 오시는 길 현재창  이동" data-sub="Y" target="_self">인재발굴처 오시는 길</a>
						           		</li>
					           		
								</ul>
							
		           	</li>
           	 	
            </ul>
		</nav>
		<div class="util">
		
			<button type="button" class="btn_topPopzone">팝업존</button>
		
			<button type="button" class="btn_topSearch">
  <img src="https://oku.korea.ac.kr/kru/type/IPSI_A/img/layout/m/ico_search_white.png" alt="검색">
  <!-- alt 속성은 이미지 설명 텍스트로 대체 텍스트를 제공합니다. -->
  검색
</button>

	    </div>
		
		<button type="button" class="btn_topSitemap"><a href="/student/login">LOGIN</a></button>
		<a href="https://oku.korea.ac.kr/oku/index.do" class="mBtn_home">메인페이지</a>
		<button type="button" class="mBtn_close">메뉴 닫기</button>
	</header>
</div>			
<script>
var gnbDep1 = 0;
var gnbDep2 = 0;
var gnbDep3 = 0;
</script>