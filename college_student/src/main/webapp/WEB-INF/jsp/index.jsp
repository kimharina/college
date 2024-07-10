<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<c:import url="/header" />
<div id="container">
	<div id="contents">
		<!-- topBnr -->
		<div class="mTopBnr" style="display: none;">
			<div class="list">
				<div class="unit">
					<a
						href="https://oku.korea.ac.kr//oku/cms/FR_BBS_CON/BoardView.do?MENU_ID=750&CONTENTS_NO=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1565"
						target="_blank"> <img
						src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=17"
						alt="2024학년도 카리나대학교 수시모집요강"> <span><img
							src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=17"
							alt="2024학년도 카리나대학교 수시모집요강"></span>
					</a>
				</div>
				<div class="unit">
					<a
						href="https://oku.korea.ac.kr/oku/cms/FR_BBS_CON/BoardView.do?pageNo=1&pagePerCnt=10&MENU_ID=750&CONTENTS_NO=4&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1581&PWD=&SEARCH_SEQ=3&SEARCH_FLD=&SEARCH="
						target="_blank"> <img
						src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=18"
						alt="2024학년도 카리나대학교 정시모집요강" /> <span><img
							src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=18"
							alt="2024학년도 카리나대학교 정시모집요강" /></span>
					</a>
				</div>
				<div class="unit">
					<a
						href="https://oku.korea.ac.kr/oku/cms/FR_BBS_CON/BoardView.do?pageNo=1&pagePerCnt=10&MENU_ID=750&CONTENTS_NO=2&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1563&PWD=&SEARCH_SEQ=1&SEARCH_FLD=&SEARCH="
						target="_blank"> <img
						src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=17"
						alt="2025학년도 입학전형 시행계" /> <span><img
							src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=17"
							alt="2025학년도 입학전형 시행계" /></span>
					</a>
				</div>
				<div class="unit">
					<a
						href="https://oku.korea.ac.kr/oku/cms/FR_BBS_CON/BoardView.do?pageNo=1&pagePerCnt=10&MENU_ID=750&CONTENTS_NO=4&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1581&PWD=&SEARCH_SEQ=3&SEARCH_FLD=&SEARCH="
						target="_blank"> <img
						src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=18"
						alt="2024학년도 카리나대학교 정시모집요강" /> <span><img
							src="https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&TEMP_CODE=IPSI_A&CONFIG_CD=C1401&CONFIG_SEQ=1&SITE_NO=2&SUB_SEQ=18"
							alt="2024학년도 카리나대학교 정시모집요강" /></span>
					</a>
				</div>
			</div>

			<div class="list_control">
				<button type="button" class="btn_pause">일시정지</button>
			</div>
			<input type="hidden" name="AUTO_ROLL_YN" value="Y" /> <input
				type="hidden" name="ROLL_TIME" value="5" />
		</div>
		<!-- //mTopBnr -->
		<!-- linkBnr -->

		<script>
			$(document)
					.ready(
							function() {
								$('.mLinkBnr .unit > div').removeClass(
										'slick-current');
								$('.mLinkBnr .unit')
										.hover(
												function() {

													//				  $('.mLinkBnr .unit.over.slick-current>div').attr('style', 'margin-top:0 !important;');
													$(
															'.mLinkBnr .unit.over.slick-current>div')
															.css("opacity", "1");

												},
												function() {
													//				  $('.mLinkBnr .unit.over.slick-current>div').attr('style', 'margin-top:-20px !important;');
													$(
															'.mLinkBnr .unit.over.slick-current>div')
															.css("opacity", "1");
												});
							});
		</script>
		<div class="mLinkBnr" style="display: none;">
			<div class="list">
				<div class="unit">
					<div>
						<a href="" target="_self" style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1405&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=1)">
							<strong>공지사항</strong> <span class="txt">인재발굴처<br />공지사항
						</span> <span class="btn">바로가기</span>
						</a>
					</div>
				</div>
				<div class="unit">
					<div>
						<a href="https://www.youtube.com/c/aokorea" target="_blank"
							style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1405&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=6)">
							<strong>인재발굴처<br />Youtube
						</strong> <span class="txt">인재발굴처<br />Youtube 바로가기
						</span> <span class="btn">바로가기</span>
						</a>
					</div>
				</div>
				<div class="unit">
					<div>
						<a
							href="https://oku.korea.ac.kr/oku/cms/FR_CON/index.do?MENU_ID=720"
							target="_self"
							style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1405&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=5)">
							<strong>기출문제</strong> <span class="txt">카리나대학교<br />전형별
								기출문제
						</span> <span class="btn">바로가기</span>
						</a>
					</div>
				</div>
				<div class="unit">
					<div>
						<a
							href="/student/login"
							target="_self"
							style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1405&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=4)">
							<strong>수강신청<!-- <br/>도착 확인 --></strong> <span class="txt">신입생/재학생<br />수강신청
						</span> <span class="btn">바로가기</span>
						</a>
					</div>
				</div>
			</div>
		</div>
		<!-- //linkBnr -->

		<dl class="mNoti">
			<dt>전화상담</dt>
			<dd>
				<p class="time">
					<b>평일</b> 9:00 ~ 17:30 (공휴일, 중식시간 제외)
				</p>
				<span class="telNum">010-7251-0815</span>
			</dd>
		</dl>

		<div class="mBbs">
			<div class="bbsTab">
				<ul>
					<li class="on">
						<button type="button">전체</button>
					</li>
					<li class="">
						<button type="button">일반사항</button>
					</li>
					<li class="">
						<button type="button">수시모집</button>
					</li>
					<li class="">
						<button type="button">정시모집</button>
					</li>
					<li class="">
						<button type="button">편입학</button>
					</li>
					<li class="">
						<button type="button">특별전형</button>
					</li>
				</ul>
			</div>
			<div class="bbsList">
				<div class='bbs on'>
					<ul>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1591"
							title="2024학년도 편입학 원서접수 안내 상세 이동"> <strong class="tit">2024학년도
									편입학 원서접수 안내</strong>
								<p class="txt">2024학년도 편입학 원서접수 안내</p> <span class="date">2023.12.04</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1592"
							title="2023년 KU 전공체험강의실(KU Lecture)참가 안내 상세 이동"> <strong
								class="tit">2023년 KU 전공체험강의실(KU Lecture)참가 안내</strong>
								<p class="txt"></p> <span class="date">2023.11.28</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1590"
							title="2024학년도 편입학 모집요강 상세 이동"> <strong class="tit">2024학년도
									편입학 모집요강</strong>
								<p class="txt">2024학년도 편입학 모집요강</p> <span class="date">2023.11.28</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1216"
							title="고교별 합격자 조회 서비스 사용 안내 상세 이동"> <strong class="tit">고교별
									합격자 조회 서비스 사용 안내</strong>
								<p class="txt">카리나대학교 인재발굴처 고교별 합격자 조회 서비스 사용 안내입니다.</p> <span
								class="date">2023.11.21</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1589"
							title="2024학년도 수시모집 계열적합전형, 고른기회전형, 재직자전형 최종합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 수시모집 계열적합전형, 고른기회전형, 재직자전형 최종합격자 발표</strong>
								<p class="txt">2024학년도 수시모집 계열적합전형, 고른기회전형, 재직자전형 최종합격자 발표</p> <span
								class="date">2023.11.21</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1588"
							title="2024학년도 수시모집 학업우수전형 1단계 합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 수시모집 학업우수전형 1단계 합격자 발표</strong>
								<p class="txt">2024학년도 수시모집 학업우수전형 1단계 합격자 발표</p> <span
								class="date">2023.11.16</span>
						</a></li>
					</ul>
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=1"
						target="_self" class="btn_more">더보기</a>
				</div>
				<div class='bbs '>
					<ul>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1592"
							title="2023년 KU 전공체험강의실(KU Lecture)참가 안내 상세 이동"> <strong
								class="tit">2023년 KU 전공체험강의실(KU Lecture)참가 안내</strong>
								<p class="txt"></p> <span class="date">2023.11.28</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1216"
							title="고교별 합격자 조회 서비스 사용 안내 상세 이동"> <strong class="tit">고교별
									합격자 조회 서비스 사용 안내</strong>
								<p class="txt">카리나대학교 인재발굴처 고교별 합격자 조회 서비스 사용 안내입니다.</p> <span
								class="date">2023.11.21</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1577"
							title="2023학년도 카리나대학교 모의논술고사 - 논술 자료집 안내 상세 이동"> <strong
								class="tit">2023학년도 카리나대학교 모의논술고사 - 논술 자료집 안내</strong>
								<p class="txt">2023학년도 카리나대학교 모의논술고사 - 논술 자료집 안내</p> <span
								class="date">2023.09.01</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1569"
							title="2023년 권역별 교사간담회(5회차) 추가 운영 안내  상세 이동"> <strong
								class="tit">2023년 권역별 교사간담회(5회차) 추가 운영 안내 </strong>
								<p class="txt"></p> <span class="date">2023.05.30</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1563"
							title="2025학년도 카리나대학교 입학전형시행계획 상세 이동"> <strong class="tit">2025학년도
									카리나대학교 입학전형시행계획</strong>
								<p class="txt">2025학년도 카리나대학교 입학전형시행계획</p> <span class="date">2023.04.28</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1564"
							title="2024학년도 검정고시 대입전형자료 온라인 제공 신청 방법 안내 상세 이동"> <strong
								class="tit">2024학년도 검정고시 대입전형자료 온라인 제공 신청 방법 안내</strong>
								<p class="txt">2024학년도 검정고시 대입전형자료 온라인 제공 신청 방법 안내</p> <span
								class="date">2023.04.05</span>
						</a></li>
					</ul>
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=3"
						target="_self" class="btn_more">더보기</a>
				</div>
				<div class='bbs '>
					<ul>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1589"
							title="2024학년도 수시모집 계열적합전형, 고른기회전형, 재직자전형 최종합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 수시모집 계열적합전형, 고른기회전형, 재직자전형 최종합격자 발표</strong>
								<p class="txt">2024학년도 수시모집 계열적합전형, 고른기회전형, 재직자전형 최종합격자 발표</p> <span
								class="date">2023.11.21</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1588"
							title="2024학년도 수시모집 학업우수전형 1단계 합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 수시모집 학업우수전형 1단계 합격자 발표</strong>
								<p class="txt">2024학년도 수시모집 학업우수전형 1단계 합격자 발표</p> <span
								class="date">2023.11.16</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1587"
							title="2024학년도 수시모집 계열적합전형 1단계 합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 수시모집 계열적합전형 1단계 합격자 발표</strong>
								<p class="txt">2024학년도 수시모집 계열적합전형 1단계 합격자 발표</p> <span
								class="date">2023.11.03</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1586"
							title="2024학년도 수시모집 사이버국방학과 온라인 신원조사(구비서류 제출 등) 및 인성검사 안내 상세 이동">
								<strong class="tit">2024학년도 수시모집 사이버국방학과 온라인 신원조사(구비서류
									제출 등) 및 인성검사 안내</strong>
								<p class="txt">2024학년도 수시모집 사이버국방학과 온라인 신원조사(구비서류 제출 등) 및
									인성검사 안내</p> <span class="date">2023.10.27</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1583"
							title="2024학년도 수시모집 고른기회전형, 재직자전형 1단계 합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 수시모집 고른기회전형, 재직자전형 1단계 합격자 발표</strong>
								<p class="txt">2024학년도 수시모집 고른기회전형, 재직자전형 1단계 합격자 발표</p> <span
								class="date">2023.10.27</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1585"
							title="2024학년도 수시모집 사이버국방전형, 특기자전형 1단계 합격자 발표  상세 이동"> <strong
								class="tit">2024학년도 수시모집 사이버국방전형, 특기자전형 1단계 합격자 발표 </strong>
								<p class="txt">2024학년도 수시모집 사이버국방전형, 특기자전형 1단계 합격자 발표</p> <span
								class="date">2023.10.27</span>
						</a></li>
					</ul>
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=8"
						target="_self" class="btn_more">더보기</a>
				</div>
				<div class='bbs '>
					<ul>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=10&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1581"
							title="2024학년도 정시모집요강(2023.11.수정) 상세 이동"> <strong class="tit">2024학년도
									정시모집요강(2023.11.수정)</strong>
								<p class="txt">2024학년도 정시모집요강(2023.11.수정)</p> <span class="date">2023.09.01</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=10&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1562"
							title="2024학년도 정시모집 수능-교과우수전형 학생부(교과)점수 산출 예시 상세 이동"> <strong
								class="tit">2024학년도 정시모집 수능-교과우수전형 학생부(교과)점수 산출 예시</strong>
								<p class="txt">2024학년도 정시모집 수능-교과우수전형 학생부(교과)점수 산출 예시</p> <span
								class="date">2023.04.05</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=10&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1514"
							title="2023학년도 정시모집 대학수학능력시험 변환점수/점수산출 안내 상세 이동"> <strong
								class="tit">2023학년도 정시모집 대학수학능력시험 변환점수/점수산출 안내</strong>
								<p class="txt">2023학년도 정시모집 대학수학능력시험 변환점수/점수산출 안내</p> <span
								class="date">2022.12.22</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=10&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1486"
							title="기회균등-특성화고교졸업자 동일계열 기준학과 및 전문교과 안내(2022.07 update) 상세 이동">
								<strong class="tit">기회균등-특성화고교졸업자 동일계열 기준학과 및 전문교과
									안내(2022.07 update)</strong>
								<p class="txt">기회균등-특성화고교졸업자 동일계열 기준학과 및 전문교과 안내</p> <span
								class="date">2022.07.26</span>
						</a></li>
					</ul>
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=10"
						target="_self" class="btn_more">더보기</a>
				</div>
				<div class='bbs '>
					<ul>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=11&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1591"
							title="2024학년도 편입학 원서접수 안내 상세 이동"> <strong class="tit">2024학년도
									편입학 원서접수 안내</strong>
								<p class="txt">2024학년도 편입학 원서접수 안내</p> <span class="date">2023.12.04</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=11&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1590"
							title="2024학년도 편입학 모집요강 상세 이동"> <strong class="tit">2024학년도
									편입학 모집요강</strong>
								<p class="txt">2024학년도 편입학 모집요강</p> <span class="date">2023.11.28</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=11&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1568"
							title="2024학년도 편입학전형 자연계 필기고사 출제범위 및 참고도서 상세 이동"> <strong
								class="tit">2024학년도 편입학전형 자연계 필기고사 출제범위 및 참고도서</strong>
								<p class="txt">2024학년도 편입학전형 자연계 필기고사 출제범위 및 참고도서</p> <span
								class="date">2023.05.26</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=11&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1505"
							title="2023학년도 편입학전형 모집요강 상세 이동"> <strong class="tit">2023학년도
									편입학전형 모집요강</strong>
								<p class="txt">2023학년도 편입학전형 모집요강</p> <span class="date">2022.11.30</span>
						</a></li>
					</ul>
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=11"
						target="_self" class="btn_more">더보기</a>
				</div>
				<div class='bbs '>
					<ul>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=9&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1580"
							title="2024학년도 특별전형(전기) 최종 합격자 발표 상세 이동"> <strong class="tit">2024학년도
									특별전형(전기) 최종 합격자 발표</strong>
								<p class="txt">2024학년도 특별전형(전기) 최종 합격자 발표</p> <span class="date">2023.09.06</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=9&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1576"
							title="2024학년도 특별전형(전기) 디자인조형학부 면접고사 안내 상세 이동"> <strong
								class="tit">2024학년도 특별전형(전기) 디자인조형학부 면접고사 안내</strong>
								<p class="txt">2024학년도 특별전형(전기) 디자인조형학부 면접고사 안내</p> <span
								class="date">2023.08.03</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=9&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1575"
							title="2024학년도 특별전형(전기) 1단계 합격자 발표 상세 이동"> <strong
								class="tit">2024학년도 특별전형(전기) 1단계 합격자 발표</strong>
								<p class="txt">2024학년도 특별전형(전기) 1단계 합격자 발표</p> <span
								class="date">2023.08.03</span>
						</a></li>
						<li><a
							href="/oku/cms/CMN_CON/MainLink.do?GBN=BA&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=9&SITE_NO=2&BOARD_SEQ=5&BBS_SEQ=1566"
							title="2024학년도 특별전형(전기) 모집요강 상세 이동"> <strong class="tit">2024학년도
									특별전형(전기) 모집요강</strong>
								<p class="txt">2024학년도 특별전형(전기) 모집요강</p> <span class="date">2023.05.31</span>
						</a></li>
					</ul>
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=BL&TEMP_CODE=IPSI_A&BASE_SITE_NO=2&CONFIG_CD=C1406&CONFIG_SEQ=1&SUB_SEQ=9"
						target="_self" class="btn_more">더보기</a>
				</div>
			</div>
		</div>
		<!-- schedule -->
		<!-- C1408 -->
		<div class="mSchedule">
			<div class="calendar">
				<form id="schFrm" method="post">
					<input type="hidden" name="SITE_NO" value="2" /> <input
						type="hidden" name="TEMP_CODE" value="IPSI_A" /> <input
						type="hidden" name="CONFIG_CD" value="C1408" /> <input
						type="hidden" name="CONFIG_SEQ" value="1" />
				</form>

				<div class="calendarM">
					<button type="button" class="btn_prev btnm" data-move="prev">이전</button>
					<b id="move_calendar">2023.12</b>
					<button type="button" class="btn_next btnm" data-move="next">다음</button>
				</div>

				<ul class="calendarD">
					<li class="fri">01</li>
					<li class="sat">02</li>
					<li class="sun">03</li>
					<li class="mon">04</li>
					<li class="tue">05</li>
					<li class="wed">06</li>
					<li class="thu">07</li>
					<li class="fri">08</li>
					<li class="sat">09</li>
					<li class="sun">10</li>
					<li class="mon">11</li>
					<li class="tue">12</li>
					<li class="wed">13</li>
					<li class="thu">14</li>
					<li class="fri">15</li>
					<li class="sat">16</li>
					<li class="sun">17</li>
					<li class="mon">18</li>
					<li class="tue">19</li>
					<li class="wed">20</li>
					<li class="thu">21</li>
					<li class="fri">22</li>
					<li class="sat">23</li>
					<li class="sun">24</li>
					<li class="mon">25</li>
					<li class="tue">26</li>
					<li class="wed">27</li>
					<li class="thu">28</li>
					<li class="fri">29</li>
					<li class="sat">30</li>
					<li class="sun">31</li>
				</ul>
			</div>

			<div class="scheduleList">
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="CK"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.05(화) ~ 07(목) </span>
						<p>'24 편입학 원서접수</p>
					</a>
				</div>
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="-"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.15(금) </span>
						<p>'24 수시모집 최종합격자 발표(2)</p>
					</a>
				</div>
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="-"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.16(토) </span>
						<p>'24 편입학 필기고사</p>
					</a>
				</div>
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="-"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.18(월) ~ 21(목) </span>
						<p>'24 수시모집 합격자 등록</p>
					</a>
				</div>
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="-"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.18(월) ~ 21(목) </span>
						<p>'24 특별전형 합격자 등록</p>
					</a>
				</div>
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="-"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.22(금) ~ 28(목) </span>
						<p>'24 특별전형 미등록 충원</p>
					</a>
				</div>
				<div class="unit">
					<a
						href="/oku/cms/CMN_CON/MainLink.do?GBN=SCH&BASE_SITE_NO=2&BASE_MENU_NO=1060"
						data-check="-"> <span class="dateY">2023</span> <span
						class="dateMD"> 12.22(금) ~ 29(금) </span>
						<p>'24 수시모집 미등록 충원</p>
					</a>
				</div>
			</div>
			<div class="no_scheduleList" style='display: none'>
				<p class="no_article">등록된 일정이 없습니다.</p>
			</div>
		</div>
		<!-- //schedule -->
		<!-- icoBnr -->
		<div class="mIcoBnr">
			<ul class="list">
				<ul class="list">
					<li><a
						href="https://oku.korea.ac.kr/oku/cms/FR_CON/index.do?MENU_ID=740"
						target="_self" title="현재창"
						style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1402&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=2)">
							모집요강</a></li>
					<li><a
						href="https://oku.korea.ac.kr/oku/cms/FR_CON/index.do?MENU_ID=730"
						target="_self" title="현재창"
						style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1402&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=3)">
							제출서류 양식</a></li>
					<li><a
						href="https://oku.korea.ac.kr/oku/cms/FR_CON/index.do?MENU_ID=790"
						target="_self" title="현재창"
						style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1402&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=6)">
							FAQ</a></li>
					<li><a
						href="https://oku.korea.ac.kr/oku/cms/FR_CON/index.do?MENU_ID=1540"
						target="_self" title="현재창"
						style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1402&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=1)">
							Q&A</a></li>
					<li><a href="/oku/cms/FR_CON/index.do?MENU_ID=760"
						target="_self" title="현재창"
						style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1402&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=5)">
							입학설명회 동영상</a></li>
					<li><a
						href="http://www.korea.ac.kr/mbshome/mbs/university/subview5.jsp?id=university_010501000000"
						target="_self" title="현재창"
						style="background-image: url(https://oku.korea.ac.kr/ajaxfile/CMN_SVC/FileView.do?GBN=X04&amp;TEMP_CODE=IPSI_A&amp;CONFIG_CD=C1402&amp;CONFIG_SEQ=1&amp;SITE_NO=2&amp;SUB_SEQ=4)">
							캠퍼스맵</a></li>
				</ul>
			</ul>
		</div>
	</div>
</div>
<!-- //container -->
<c:import url="/footer" />