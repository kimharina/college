$(function(){
	//*** gnb(pc)
	function navSub_size(){
		if(window.innerWidth >= 1380){
			for(i=0; i<$("header>nav #gnb>li").length; i++){
				$("header>nav #gnb>li:nth-child(" + (i+1) + ")").css({
					"width": $("header>nav #gnb_parent>li").eq(i).width() + 134
				});
			}
		}else if(window.innerWidth >= 1041 && window.innerWidth < 1380){
			for(i=0; i<$("header>nav #gnb>li").length; i++){
				$("header>nav #gnb>li:nth-child(" + (i+1) + ")").css({
					"width": $("header>nav #gnb_parent>li").eq(i).width() + 76
				});
			}
		}else{
			$("header>nav #gnb>li").css("width","")
		}
	}

	/*$("#header nav").on('mouseover', function(){
		if(window.innerWidth >= 1041){
			$("#dim").addClass('on');
			$("#header").css("transition","0.2s").addClass('on');
			$("#header").css("height", $("header>nav #gnb").height() + 170);

			if($("#header").attr('class') == 'searchOn' || $("#header").attr('class') == 'gnbOn searchOn'){
			}else{
				//$("#header").addClass('on gnbOn');
				$("#dim").addClass('on');
				$("#header").css("transition","0.2s").addClass('on');
			}
		}
	});*/

	$("#header nav>ul>li>a").on('mouseover', function(){
		if(window.innerWidth >= 1041){
			$("#dim").addClass('on');
			$("#header").css("transition","0.2s").addClass('on');
			$("#header").css("height", $("header>nav #gnb").height() + 180);
			//$("#header nav .top_navTit").removeClass('on');
			$("#header nav .menuM").removeClass('on')
			//$(this).siblings('p').addClass('on');
			//$(this).siblings('ul').addClass('on');

			if($("#header").attr('class') == 'searchOn' || $("#header").attr('class') == 'gnbOn searchOn'){
			}else{
				$("#header nav>ul>li>a").removeClass('on');
				$(this).addClass('on');
				$("#header, #dim").addClass('on');
				//$("#header nav .top_navTit").removeClass('on');
				$("#header nav .menuM").removeClass('on');
				//$(this).siblings('p').addClass('on');
				//$(this).siblings('ul').addClass('on');
			}
		}
	});

	$("#header").on('mouseleave', function(){
		if(window.innerWidth >= 1041){
			$("#header, #dim").removeClass('on');
			$("#header nav>ul>li>a, .menuM").removeClass('on');
			$("#header").css("height", "");

			var headerLoc = $(window).scrollTop();
			if(headerLoc <= 1){
				$("#header").removeClass('on');
			}
		}
	});

	$("#header .util").on('mouseover', function(){
		if(window.innerWidth >= 1041){
			$("#header, #dim").removeClass('on');
			$("#header nav>ul>li>a, .menuM").removeClass('on');
			$("#header").css("height", "");

			var headerLoc = $(window).scrollTop();
			if(headerLoc <= 1){
				$("#header").removeClass('on');
			}
		}
	});

	//*** gnb(mobile)
	var mBtnMenu_onLoc;
	var mConts_loc;
	$(window).bind('load scroll', function(){
		mConts_loc = $("html, body").scrollTop();
		/*console.log(mConts_loc);*/
	});

	$("header .mBtn_topMenu").click(function(){
		if($(this).hasClass('on')){
			mMenuClose();
		}else{
			$("html").css({"overflow": "hidden"});
			/*$("body").css({"overflow-y": "scroll"});*/ /*190616수정*/
			$("body").css({"overflow-y": "hidden"}); /*190616수정*/

			if(window.innerWidth > 768 && window.innerWidth < 1041){
				$("#gnb_dim, header .siteCateg, header nav, header .util").addClass('on');

				/*$("body").stop().animate({
					"left":  window.innerWidth - 80
				}, 200);*/
				$("header .siteCateg").stop().animate({
					"left":"0"
				}, 200);
				$("header .mBtn_topMenu").addClass('on').stop().animate({
					"left": $("body").width() - $("header .mBtn_topMenu").width()
				}, 200);
				$("header nav").stop().animate({
					"left":"0"
				}, 200);
				$("header .btn_topSitemap").stop().animate({
					"left":"20px"
				}, 200);
				$("header .mBtn_home").stop().animate({
					"left": $("#gnb>li").width() - 25
				}, 200);
				$("header .mBtn_close").stop().animate({
					"left": $("#gnb>li").width() + 30
				}, 200);

				$("header .siteCateg").css("width", window.outerWidth - 80);
				//$("header nav").css("width", $("body").width() - 63);
			}
			if(window.innerWidth <= 768){
				$("#gnb_dim, header .siteCateg, header nav, header .util").addClass('on');

				/*$("body").stop().animate({
					"left":  window.innerWidth - 40
				}, 200);*/
				$("header .siteCateg").stop().animate({
					"left":"0"
				}, 200);
				$("header .mBtn_topMenu").addClass('on').stop().animate({
					"left": $("body").width() - $("header .mBtn_topMenu").width()
				}, 200);
				$("header nav").stop().animate({
					"left":"0"
				}, 200);
				$("header .btn_topSitemap").stop().animate({
					"left":"20px"
				}, 200);
				$("header .mBtn_home").stop().animate({
					"left": $("#gnb>li").width() - 30
				}, 200);
				$("header .mBtn_close").stop().animate({
					"left": $("#gnb>li").width()
				}, 200);

				$("header .siteCateg").css("width", window.outerWidth - 40);
				//$("header nav").css("width", $("body").width() - 23);
			}

			/*$("header nav").css("width", $("header .siteCateg").width());*/
			$("header>nav>ul>li>a.on").siblings('ul').show();

			mBtnMenu_onLoc = mConts_loc
			$(".popZone .btn .btn_popZone_close").trigger('click');

			$("html").css({"overflow": "hidden"});
			/*$("body").css({"overflow-y": "scroll"});*/ /*190616수정*/
			$("body").css({"overflow-y": "hidden"}); /*190616수정*/
		}
	});

	$("header .mBtn_topMenu.on, header .mBtn_close").click(function(){
		mMenuClose();
	});

	function mMenuClose(){
		$("#gnb_dim, header .siteCateg, header nav, header .util").removeClass('on');

		$("html, body").removeAttr('style');
		$("html, body").stop().animate({
			scrollTop: mBtnMenu_onLoc
		}, 0);
		/*$("body").stop().animate({
			"margin-left": "0"
		}, 200);*/
		$("header .siteCateg").stop().animate({
			"left":"-1041px"
		}, 200);
		$("header .mBtn_topMenu").removeClass('on').stop().animate({
			"left":"0"
		}, 200);
		$("header nav").stop().animate({
			"left":"-1041px"
		}, 200);
		$("header .btn_topSitemap").stop().animate({
			"left":"-1041px"
		}, 200);
		$("header .mBtn_home").stop().animate({
			"left":"-1041px"
		}, 200);
		$("header .mBtn_close").stop().animate({
			"left":"-1041px"
		}, 200);

		$("header .siteCateg, header nav").css("width", "");
	}

	//1depth
	$("header>nav>ul>li>a").click(function(){
		if(window.innerWidth < 1041){
			if($(this).siblings('ul').tagName = 'ul'){
				if($(this).attr('class') != 'on'){
					$("body").css("overflow","hidden");
					$("header>nav>ul>li>a").removeClass('on');
					$("header>nav>ul .menuM").removeClass('on').slideUp(200);
					$("header>nav>ul .menuS").removeClass('on').slideUp(200);

					$(this).addClass('on').slideDown(200);
					$(this).siblings('ul').addClass('on').slideDown(200);

					if($(this).parent().find("ul").length > 0) return false;
				}else{
					return false;
				}
			}
		}
	});
	//2depth
	$("header>nav>ul .menuM>li>a").click(function(){
		if(window.innerWidth < 1041){
			if($(this).siblings('ul').tagName = 'ul'){
				$("header>nav>ul .menuM>li>a").removeClass('on');
				$("header>nav>ul .menuS").removeClass('on').slideUp(200);

				$(this).addClass('on').slideDown(200);
				$(this).next('ul').addClass('on').slideDown(200);

				if($(this).parent().find("ul").length > 0) return false;
			}else{
				return true;
			}
		}
	});

	//*** popZone
	/*var popZone_popSize;
	var funcMotion_set = null;
	$("header .util .btn_topPopzone").click(function(){
		if(window.innerWidth >= 1041){
			$("body").css({
				"overflow":"hidden"
			});
			if($("body").hasClass('typeHeadBnr')){
				$(".popZone").addClass('on').css("height", window.innerHeight - 256);
			}else{
				$(".popZone").addClass('on').css("height", window.innerHeight - 116);
			}
		}else{$("body").css({
			"overflow":"hidden",
			"position":"fixed"
		});
			$(".popZone").addClass('on').css("height", window.innerHeight - $("header").height());
		}

		$(".popZone .list").chromaGallery();*/

		/*if(getCookie("pop_zone") == "done"){
			$(".popZone input:checkbox").prop("checked",true);
		}*/

		/*setFunc();
		popZone_size();
	});
	if(funcMotion_set == null){
		setFunc();
	}
	function setFunc() {
		funcMotion_set = setTimeout(function(e){popZone_popSize = $(".popZone .list").height();}, 500);
	}
	function clearFunc() {
		clearTimeout(funcMotion_set);
	}

	var popZone_reset = $(".popZone .list").html();
	$(".popZone .btn .btn_popZone_close").click(function() {
		$("body").css({
			"overflow":"",
			"position":""
		});
		$(".popZone").removeClass('on');
		$(".popZone .list").chromaGallery('destroy');
		$(".popZone .list").removeAttr('style').removeClass('chroma-gallery').html(popZone_reset);
		$(".popZone").css("height","");
	});*/

	$(".popZone").mCustomScrollbar({
		mouseWheelPixels : 300, // 마우스휠 속도
		scrollInertia : 400, // 부드러운 스크롤 효과 적용
		contentTouchScroll : true,  // 터치 스크롤
		advanced:{
		  updateOnContentResize: true
	  	}
	});

	/* 개발단에서 show/hide 제어하기로 함(여기 setTimeout은 퍼블확인용/개발단 전달할땐 hidden 처리)*/
	/*setTimeout(function(){
		$(".popZone").hide();
	},1000);*//*190717추가*/


	var popzone_locSet //팝업존 위치 셋팅
	var popzone_userLoc // 유저 컨텐츠 위치
	var classSet // class 셋팅
	$(".btn_topPopzone").click(function(){
		popzone_userLoc = mConts_loc
		//classSet = $("body").attr('class');
		//$("body").removeAttr('class');

		$(".popZone").show();/*190717추가*/
		$('html').css('overflow','hidden');
		$('body').css('overflow-y','scroll');

		popzone_locSet = $(".popZone .list").height();

		popZone_size();

		$(".popZone").addClass('on');
		$("#pop_dim").addClass('on').css("z-index","2000");

		$("html, body").animate({
			scrollTop: popzone_userLoc
		}, 0);

		/*$("body").removeAttr('class').attr("class", classSet);
		if(popzone_userLoc > 0){
			$("#header").addClass('gnbOn');
		}*/

		if($("body").hasClass('typeHeadBnr')){
			if(popzone_userLoc > 150){
				$("body").addClass('popSticky');
			}else{
				$("body").removeClass('popSticky');
			}
		}

		/*190730수정 시작*/
		if($(".popZone .btn .btn_popZone_close").attr('class') != "btn_popZone_close mainPop"){
			$(".popZone .list").find('a').first().focus();
			return false;
		}
		/*190730수정 끝*/
	});

	function popZone_size(){
		if(window.innerWidth > 1041){
			var conts_load = $("body").offset().top;
			var popConts_h = $(".popZone .list").height();

			//$(".popZone").css({"bottom": -(popConts_h)});

			if($("body").hasClass('typeHeadBnr') && popzone_userLoc == 0){
				$(".popZone").css({
					"bottom": 0,
					"height": window.innerHeight - 166 - 100
				})
			}else if($("body").hasClass('typeHeadBnr') && popzone_userLoc > 0 && popzone_userLoc < 150){
				$(".popZone").css({
					"bottom": 0,
					"height": window.innerHeight - $("#headTop_bnr").height() - $("#header").height() + popzone_userLoc
				})
			}else{
				$(".popZone").css({
					"bottom": 0,
					"height": window.innerHeight - 116
				})
			}
			if(popConts_h < $(".popZone").height()){
				$(".popZone").css("height", popConts_h + 80);
			}
		}

		if(window.innerWidth > 768 && window.innerWidth < 1041 ){
			var win_size = window.innerHeight - 80;
			var conts_size = $(".popZone .list").height();
			if(conts_size > win_size){
				$(".popZone").css({
					"height": window.innerHeight - 80
				});
				$(".popZone").addClass('popFix');
			}else{
				$(".popZone").css({
					"height": ""
				});
				$(".popZone").removeClass('popFix');
			}
		}
		if(window.innerWidth <= 768){
			var win_size = window.innerHeight - 40;
			var conts_size = $(".popZone .list").height();
			if(conts_size > win_size){
				$(".popZone").css({
					"height": window.innerHeight - 40
				});
				$(".popZone").addClass('popFix');
			}else{
				$(".popZone").css({
					"height": ""
				});
				$(".popZone").removeClass('popFix');
			}
		}
	}

	$(".popZone .btn .btn_popZone_close").click(function() {
		$("html").css("overflow", "");
		$("body").removeClass('popSticky').css("overflow-y", "");

		$("#pop_dim").removeClass('on').removeAttr('style');
		if(window.innerWidth >= 1041){
			$(".popZone").removeClass('on').css({
				"height": "",
				"bottom": -(popzone_locSet)
			});
		}else{
			$(".popZone").removeClass('on').css({
				"height": ""
			});
		}
		$(".popZone").hide();/*190717추가*/

		$("html, body").animate({
			scrollTop: popzone_userLoc
		}, 0);

		/*190730추가 시작*/
		if(!$(this).hasClass('mainPop')){
			$("header .util .btn_topPopzone").focus();
		}

		$(this).removeClass('mainPop');
		/*190730추가 끝*/

	});

	//*** quick
	$("#quick_menu .q_top>button").click(function(){
		if($("#footer").attr('class') == 'on'){
			$("#dim, #footer").removeClass('on');
			$("html, body").css("overflow","");
			$("#footer, #quick_menu .q_list, #quick_menu .q_list .sectionGrp").removeAttr('style');

			mQuick_menu();

			$("#quick_menu").removeAttr('style');
		}else{
		  $('.q_list').show(); //웹접근성 220720
			$('.q_list > div').css('max-height', '100%'); //웹접근성 220720
			$("#dim, #footer").addClass('on');
			$('.focus').focus();
			if($(window).innerWidth < 1041){
				$("html, body").css({"overflow": "hidden"});
			}else{
				$("body").css({"overflow": "hidden"});
			}

			quickSize();
		}
	});
	
	//웹접근성 220720
	$("#quick_menu .q_top>button").focus(function(){
		if($(".q_list").height() <= 0){
			$('.q_list').hide();
		}
	});

	function qNotice_list(){
		// quick 해제
		$("#dim, #footer").removeClass('on');
		$("html, body").css("overflow","");
		$("#footer, #quick_menu .q_list").removeAttr('style');

		mQuick_menu();

		$("#quick_menu").removeAttr('style');
	}

	$("#quick_menu .q_list .btn_close").click(function(){
		$("#dim, #footer").removeClass('on');
		$("html, body").css("overflow","");
		$("#footer, #quick_menu .q_list").removeAttr('style');

		mQuick_menu();

		$("#quick_menu").removeAttr('style');
		$('.q_list').hide();//웹접근성 220720
	});

	/*190618수정 시작*/
	var quick_orginH = window.innerHeight;
	function quickSize(){
		if(window.innerWidth >= 1041){
			var relative_h = $("#quick_menu .q_list #q01").height() + $("#quick_menu .q_list #q02").height() + 60;
			var absolute_h = $("#quick_menu .q_list #q03").height() + 60;

			if(relative_h > absolute_h){
				$("#quick_menu .q_list .sectionGrp").css({
					"height" : relative_h
				});
			}else{
				$("#quick_menu .q_list .sectionGrp").css({
					"height" : absolute_h
				});
			}

			$("#quick_menu .q_list").removeClass("mCS_destroyed");
			var quick_locFix = $(document).height() - $(window).height()
			$(window).animate({
				scrollTop : quick_locFix
			});

			var listH = window.innerHeight - $("#header").height() - $("#footer").height();
			var conH = $("#quick_menu .q_list .sectionGrp").height() + 85;
			if(listH > conH){
				$("#quick_menu .q_list").mCustomScrollbar("disable",true);
				$("#quick_menu .q_list").css("height", conH);
			}else{
				$("#quick_menu .q_list").mCustomScrollbar();
				$("#quick_menu .q_list").css("height", listH);
			}
		}else if(window.innerWidth > 768 && window.innerWidth < 1041){
			$("#quick_menu .q_list").mCustomScrollbar("destroy");
			$("#footer").css({
				"position": "fixed",
				"bottom" : -($("#footer").height() - 50)
			}, 150);
			$("#quick_menu .q_list").css("height", window.innerHeight - 50);
		}else{
			$("#quick_menu .q_list").mCustomScrollbar("destroy");
			$("#footer").css({
				"position": "fixed",
				"bottom" : -($("#footer").height() - 35)
			}, 150);
			$("#quick_menu .q_list").css("height", window.innerHeight - 35);
		}
	}
	/*190618수정 끝*/

	//*** scrollbar
	$(window).on("load",function(){
	   $("#quick_menu .q_list").mCustomScrollbar({
		   documentTouchScroll: true
	   });
   });

	//*** sticky
	var headerLoc
	$(window).bind('load scroll', function(){
		$("#header").css("transition","");
		$("#snb").slideUp(100);

		headerLoc = $(window).scrollTop();
		//console.log(headerLoc);
		if($("body").hasClass('typeHeadBnr')){
			if(headerLoc > 150){
				$("body").addClass('mSticky');
				$("#header").addClass('gnbOn');
			}else{
				$("body").removeClass('mSticky');
				$("#header").removeClass('gnbOn');
			}
		}else{
			if(headerLoc > 1){
				$("body").addClass('mSticky');
				$("#header").addClass('gnbOn');
			}else{
				$("body").removeClass('mSticky');
				$("#header").removeClass('gnbOn');
			}
		}

		if(window.innerWidth >= 1041){
			if(headerLoc > 305){
				$(".typeSub").addClass('stickyFix');
			}else{
				$(".typeSub").removeClass('stickyFix');
			}
		}else if(window.innerWidth > 768 && window.innerWidth < 1041){
			if(headerLoc > 250){
				$(".typeSub").addClass('stickyFix');
			}else{
				$(".typeSub").removeClass('stickyFix');
			}
		}else{
			if(headerLoc > 125){
				$(".typeSub").addClass('stickyFix');
			}else{
				$(".typeSub").removeClass('stickyFix');
			}
		}

	});

	//*** nav(web)
	var gnbCrt0 = $("#gnb>li:nth-child(" + (gnbDep1) + ")>a");
	var gnbCrt1 = $("#gnb>li:nth-child(" + (gnbDep1) + ")>a");
	var gnbCrt2 = $("#gnb>li:nth-child(" + (gnbDep1) + ")>ul>li:nth-child(" + (gnbDep2) + ") ");
	var gnbCrt3 = $("#gnb>li:nth-child(" + (gnbDep1) + ")>ul>li:nth-child(" + (gnbDep2) + ") ul li:nth-child(" + (gnbDep3) + ") a");
	var snbCrt1 = $("#snb>li:nth-child(" + (gnbDep1) + ")>a");
	var snbCrt2 = $("#snb>li:nth-child(" + (gnbDep1) + ")>ul>li:nth-child(" + (gnbDep2) + ")>a");
	var snbCrt3 = $("#snb>li:nth-child(" + (gnbDep1) + ")>ul>li:nth-child(" + (gnbDep2) + ") ul li:nth-child(" + (gnbDep3) + ") a");

	if(gnbCrt0) gnbCrt0.addClass("on");
	if(gnbCrt1) gnbCrt1.addClass("on");
	if(window.innerWidth < 1041){
		if(gnbCrt2) gnbCrt2.addClass("on").children("ul").slideDown(0);
	}
	if(gnbCrt3) gnbCrt3.addClass("on");

	if(snbCrt1) snbCrt1.parent().addClass("on");
	if(snbCrt2) snbCrt2.parent().addClass("on");
	if(snbCrt3) snbCrt3.parent().addClass("on");

	//*** sVisual
	//$(".sVisual").css("background-image","url(/type/ipsi_A/img/sVisual0" + gnbDep1 +".jpg)");
	$(".sVisual>div>strong").text($("#snb_nav .snb_area>button.on").text());

	$("#snb_nav>div>button").click(function(){
		$("#snb_nav").removeClass();
		$("body").toggleClass("lnb_on");

		if($("#snb_nav>div>button").index($(this)) != 0){
			$("#utilSnbYn").show();
		}else{
			$("#utilSnbYn").hide();
		}

		if($(this).index() == 1) {
			$("#snb_nav").addClass("active1");
		} else if(($(this).index() == 2)) {
			$("#snb_nav").addClass("active2");
		} else{
			$("#snb_nav").addClass("active3");
		};
		if($(this).hasClass("active")) {
			$(this).removeClass("active");
			$("#snb").slideUp(50);
			//$(".btn_snbView").hide();
			/*197030수정 시작*/
			if($(this).index() == 1) {
				$(this).attr("title","1레벨메뉴 축소됨");
			} else if(($(this).index() == 2)) {
				$(this).attr("title","2레벨메뉴 축소됨");
			} else{
				$(this).attr("title","3레벨메뉴 축소됨");
			};
			 /*197030수정 끝*/
		} else{
			$(this).addClass("active");
			$("#snb_nav>div>button").not(this).removeClass("active");
			$("#snb").slideDown(50).css({"width" : $(this).outerWidth(), "left" : $(this).position().left + 15});
			//$(".btn_snbView").show().css({"left" : $(this).position().left + 187});

			/*197030수정 시작*/
			if($(this).index() == 1) {
				$(this).attr("title","1레벨메뉴 선택 메뉴확장됨");
			} else if(($(this).index() == 2)) {
				$(this).attr("title","2레벨메뉴 선택 메뉴확장됨");
			} else{
				$(this).attr("title","3레벨메뉴 선택 메뉴확장됨");
			};
			 /*197030수정 끝*/
		};
	});

	$("#snb_nav .btn_snbView>a").click(function(){
		if($(this).attr('class') == 'on'){
			$(this).removeClass("on");
			$(".mSnb_menu .view").slideUp(50);
		}else{
			$(this).addClass("on");
			$(".mSnb_menu .view").slideDown(50);
		}
	});

	$("#snb").mouseleave(function(){
		$("#snb_nav>div>button").removeClass("active");
		$("#snb").slideUp(100);
		$("#utilSnbYn").hide();
		//$(".btn_snbView").hide()
	});

	//*** rnb
	$(".side_conts>.gnbTit").text(snbCrt1.text());

	var rnbMenu =  $("#gnb>li:nth-child(" + (gnbDep1) + ")>a").siblings('ul').clone();
	if(snbCrt1){
		$("#rnb_nav").html(rnbMenu);
		$("#rnb_nav").children('ul').removeAttr('class').attr('id','rnb')
		$("#rnb_nav li").remove('.add_tr');
		$("#rnb>li:nth-child(" + (gnbDep2) + ")").addClass('on');
		$("#rnb>li:nth-child(" + (gnbDep2) + ").on>ul>li:nth-child(" + (gnbDep3) + ")").addClass('on');
	}

	$("#rnb>li>a").click(function(){
		$("#rnb li>.menuS").not($("#rnb li.on>.menuS")).hide();
		$("#rnb>li").removeClass('actOn');
		$(this).parent().addClass('actOn');
		$(this).next().slideDown(200);
	});
	/*$("#rnb").mouseleave(function(){
		$("#rnb>li").removeClass('actOn');
		$("#rnb .menuS").removeAttr('style');
	});*/

	// pageTab
	$("#tabWrap .tabList").slick({
		infinite: false,
		slidesToShow: 1,
		slidesToScroll: 1,
		arrows: false,
		dots: false,
		focusOnSelect: true,
		swipeToSlide : true,
		variableWidth: true,
		responsive:[
			{
				breakpoint: 5012,
				settings: "unslick"
			},
			{
				breakpoint: 768,
				settings: {
					slidesToShow: 1,
					slidesToScroll: 1
				}
			}
		]
	});

	$("#tabWrap .tabList a").attr("tabindex","0"); /*190731수정*/

	var changeNum1;
	$(window).resize(function(){
		if(window.innerWidth <= 768 && $("body").hasClass('.typeSub')){
			if(changeNum1 == 1){
				$("#tabWrap .tabList")[0].slick.init();
				changeNum1 = 0;
			}
		}else{
			changeNum1 = 1
		}
	});

	$("#tabWrap .unit").each(function(){
		var tab_loc = $(this).index();
		if($(this).find('a').hasClass('on')){
			$('#tabWrap .tabList').slick('slickGoTo', tab_loc);
		}
		/*190730수정 시작*/
		$(this).attr('role','tabpanel');
		$(this).attr('aria-hidden','false');
		/*190730수정 끝*/
	});

	// top버튼
	$(".snb_util .btn_top, .btn_sideTop").click(function(){
		$("html, body").stop().animate({
			scrollTop : 0
		}, 150);
	});

	//zoom
	$('.snb_util .zoom').easyView({
		container: '#contents article>div',
		increaseSelector: '.btn_zoomIn',
		decreaseSelector: '.btn_zoomOut',
		//normalSelector: '.btn_zoomReset'
	});

	//share
	$("#snb_nav .snb_util .btn_share").click(function(){
		if($(this).hasClass('on')){
			$("#snb_nav .snb_util .btn_share, #snb_nav .snb_util .shareBox").removeClass('on');
		}else{
			$("#snb_nav .snb_util .btn_share, #snb_nav .snb_util .shareBox").addClass('on');
		}
	});
	$("#snb_nav .snb_util .shareBox").mouseleave(function(){
		$("#snb_nav .snb_util .btn_share, #snb_nav .snb_util .shareBox").removeClass('on');
	});

	//*** function
	function mGnb(){
		var deviceChange;
		if(window.innerWidth < 1041){
			deviceChange = 1
		}else{
			if(deviceChange = 1){
				$("#gnb_dim, header>nav, #gnb>li>a").removeClass('on');
				$("header>nav, .mBtn_close").removeAttr('style');
				deviceChange = 0;
			}
		}
	}

	function mSnb(){
		if(window.innerWidth < 1041){
			$("#snb").css("width", $(window).width() / 2);
		}else{
			$("#snb").css("width", "");
		}
	}

	function mQuick_menu(){
		if(window.innerWidth > 768 && window.innerWidth < 1041){
			$("#quick_menu").css("bottom", $("footer").height() + 60);
		}else if(window.innerWidth <= 768){
			$("#quick_menu").css("bottom", $("footer").height() + 70);
		}else{
			$("#quick_menu").css("bottom", "");
		}
		$("#quick_menu .q_list .sectionGrp").removeAttr('style'); /*190616수정*/
	}
	function slickPaging(){
		$(".slick-slider").each(function(){
			var slickPaging_num = $(this).find("li").length;
			if( slickPaging_num <= 1){
				$(this).children(".slick-dots").hide();
			}else{
				$(this).children(".slick-dots").show();
			}
		});
	}

	$(window).on('load', function(){
		//navSub_size(); // gnb 서브메뉴 사이즈
	});
	$(window).on('load resize', function(){
		mGnb(); // 모바일 gnb
		mSnb(); // snb width
		slickPaging(); // slick paging 노출
		navSub_size(); // gnb 서브메뉴 사이즈
	});

	var windowWidth = $(window).width();
	$(window).on('resize', function(){
		//*** 노출해제 **/
		// gnb 해제
		if(window.innerWidth >= 1041){
			$("#header, #dim").removeClass('on').removeAttr('style');
			$("#header nav>ul>li>a, .menuM").removeClass('on');

			var headerLoc = $(window).scrollTop();
			if(headerLoc <= 1){
				$("#header").removeClass('gnbOn');
			}
			$(".popZone").removeClass('popFix');
		}else{
	        if($(window).width() != windowWidth){
				$("#dim, #gnb_dim, header .mBtn_topMenu, nav").removeClass('on');
    			$("body").css({
    				"overflow": ""
    			});
    			$(".siteCateg, .mBtn_topMenu, header nav, .mBtn_arrClose, .btn_topSitemap, .mBtn_home, .mBtn_close").removeAttr('style');
	        }
		}

		// 팝업존 해제
		if($(window).width() != windowWidth){
			$(".popZone .btn .btn_popZone_close").trigger('click');
		}

		// quick 해제
		/*$('html, body').off('scroll touchmove mousewheel');
		$("#dim, #footer").removeClass('on');
		$("#quick_menu").css("height","");
		$("#quick_menu .q_list").removeAttr('style');*/
		if(window.innerWidth > 1041){
			$("#quick_menu .q_list .btn_close").trigger('click');
		}
	});

	window.onorientationchange = function() {
		var orientation = window.orientation;
		switch(orientation) {
		case 0:
			//alert('세로모드. 홈버튼이 아래쪽');
			if(window.innerWidth < 1041){
				$("html, body").removeAttr('style');
				mMenuClose();

				quick_orginH = window.innerWidth;
			}
			break;
		case 90:
			//alert('가로모드. 홈버튼이 오른쪽.');
			if(window.innerWidth < 1041){
				$("html, body").removeAttr('style');
				mMenuClose();

				quick_orginH = window.innerWidth;
			}
			break;
		case -90:
			//alert('가로모드. 홈버튼이 왼쪽.');
			if(window.innerWidth < 1041){
				$("html, body").removeAttr('style');
				mMenuClose();

				quick_orginH = window.innerWidth;
			}
			break;
		}
	}


	/*** 공통프로그램 개별타입 ***/
	$(".info_majorGuide .major_list .infoGrp dd>ul>li").each(function(){
		var linkNum = $(this).find("a").length;

		if(linkNum == 1){
			$(this).parent('ul').addClass('link01');
		}else if(linkNum == 0){
			$(this).parent('ul').addClass('link00');
		}else{
			$(this).parent('ul').removeClass('link01');
			$(this).parent('ul').removeClass('link00');
		}
	});

	/*190616수정 시작*/
	$(".programAppli table:has('.typeNoArticle')").each(function(){
		$(this).parent('div').addClass("noArticle_tb");
		$(this).find(".typeNoArticle").removeAttr('colspan');
	});

	$(window).bind('load', function(){
		if(window.innerWidth < 1041){
			if($("#contents:has(.limit_area)")){
				$(".limit_area").prepend("<span class='mark_swipe'></span>")
			}
		}
	});
	$(window).bind('load resize', function(){
		if(window.innerWidth < 1041){
			$(".lineTop_tbArea").bind('focusin click touch scroll', function(){
				$(".mark_swipe").remove();
			});
		}else{
			$(".mark_swipe").remove();
		}
	});
	/*190616수정 끝*/


	/*** keyboard nav ***//*190620추가*/
	$("#gnb_parent li>a").focus(function(event){
		$(this).trigger('mouseover');
	});

	var gnbNumLoc = $("#gnb_parent>li").length;
	var gnbLoc;
	$("#gnb_parent>li>a").keydown(function(event){
		gnbLoc = $(this).parent('li').index();
		//console.log(gnbLoc);

		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				if($(this).parent('li').is(':first-child')){
					$("header .siteCateg li").find('a').last().focus();
					$("#header").trigger('mouseleave');
				}else{
					$(this).removeClass('on');
					$("#gnb_parent>li:nth-child(" + (gnbLoc) + ")>a").addClass('on');
					$("#gnb>li:nth-child(" + (gnbLoc) + ") .menuM>li:last-child").find('a').first().focus();
				}
				gnbLoc = gnbLoc - 1;
				return false;
			}else{
				$("#gnb>li:nth-child(" + (gnbLoc+1) + ") .menuM>li:first-child").find('a').first().focus();
				return false;
			}
		}
	});
	$("#gnb .menuM>li>a").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				if($(this).parent('li').is(':first-child')){
					$("#gnb_parent>li").eq(gnbLoc).find('a').first().focus();
					return false;
				}
			}else{
				if($(this).parent('li').is(':last-child')){
					if(gnbLoc+1 != gnbNumLoc){
						$("#gnb_parent>li").eq(gnbLoc+1).find('a').first().focus();
					}else{
						$("#header").removeAttr('style');
						$("#header .util").trigger('mouseover');
						$("header .util").find('button').first().focus();
					}
					return false;
				}
			}
		}
	});

	$("header .util button:first-child").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				//gnbLoc = $("#gnb_parent>li").length - 1;
				$("#gnb_parent li>a").trigger('mouseover');
				$("#gnb_parent>li:last-child").find('a').first().focus();
				//$("#gnb>li:last-child .menuM>li:last-child").find('a').first().focus();
				return false;
			}else{}
		}
	});

	/*190730수정 시작*/
	$("header .util .btn_topPopzone").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 13){
			$(this).trigger('click');
			return false;/*190729수정*/
		}
	});
	/*190730수정 끝*/
	$(".popZone .list>a:first-child").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				$(".popZone .btn>.btn_popZone_close").focus();
				return false;
			}
		}
	});

	/* 아래 trigger는 팝업존 페이지 로딩 on 테스트 설정값(실제 운영에서는 개발단에서 조정 / 운영반영시 hidden처리) */
	//$(".btn_topPopzone").trigger('click');

	/*190721 시작*/
	$(".popZone .btn>.btn_popZone_close").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				$(".popZone .btn>.limit input").focus();
				return false;
			}else{
				$(".popZone .list").find("a").first().focus();
				return false;
			}
		}
		if(v_keyCode == 13){
			$(this).trigger('click');
			$("#headTop_bnr .bnr_area .list .bnr>a").focus();
			return false;
		}
	});
	/*190721 끝*/

	$("header .util .btn_topSearch").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 13){
			$(this).trigger('click');
			/*$("#iframeSearchPop").contents().find('input').first().focus();*/ /*190730 수정*/
			return false;
		}
	});

	/*190717수정 시작*/
	$("header .btn_topSitemap").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 13){
			$(this).trigger('click');
			/*$("#iframeSitePop").contents().find('#map01').find('a').first().focus();*/ /*190730 수정*/
			return false;
		}
	});

	$("#snb_nav .snb_area>button").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 13){
			/*$(this).attr("title","주메뉴 선택, 메뉴 확장");*/ /*190730수정*/
		}
		if(v_keyCode == 9){
			if(event.shiftKey){
				$("#snb_nav .snb_area>button.active").trigger('click');
			}else{
				if($(this).hasClass('active')){
					if($("#snb_nav").hasClass("active1")){
						$("#snb_nav #snb>li:first-child").find('a').focus();
					}
					if($("#snb_nav").hasClass("active2")){
						$("#snb_nav #snb>li>ul>li:first-child").find('a').focus();
					}
					if($("#snb_nav").hasClass("active3")){
						$("#snb_nav #snb>li>ul>li>ul>li:first-child").find('a').focus();
					}
					return false;
				}

			}
		}
	});
	$("#snb_nav #snb li:first-child>a").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				/*190802수정 시작*/
				$("#snb_nav .snb_area").find('.active').trigger('click').focus();
				if($("#snb_nav").hasClass("active1")) {
					$("#snb_nav .snb_area>button.active").attr("title","1레벨메뉴 축소됨");
				}
				if($("#snb_nav").hasClass("active2")) {
					$("#snb_nav .snb_area>button.active").attr("title","2레벨메뉴 축소됨");
				}
				if($("#snb_nav").hasClass("active3")) {
					$("#snb_nav .snb_area>button.active").attr("title","3레벨메뉴 축소됨");
				}
				 /*190802수정 끝*/
				return false;
			}else{
			}
		}
	});
	$("#snb_nav #snb li:last-child>a").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
			}else{
				if($("#snb_nav .snb_area .active").hasClass("on")){
					$("#snb_nav .snb_area").find('.active').trigger('click');
					$("#snb_nav .snb_util").find('button').first().focus();
				}else{
					/*190730수정 시작*/
					$("#snb_nav .snb_area").find('.active');
					/*190730수정 끝*/
					$("#snb_nav .snb_area").find('.active').trigger('click').next().focus();
				}
				return false;
			}
		}
	});
	/*190717수정 끝*/

	var quickLoc;
	$("#quick_menu .q_top>.btn_menu").click(function(event){
		quickLoc = $(this).index();

		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
			}else{
				if(quickLoc == 2){
					$("footer .f_menu li:first-child").find('a').first().focus();
					return false;
				}
			}
		}
		if(v_keyCode == 13){
			$("#footer").addClass('on');

			quickSize();

			if(quickLoc == 0){
				$("#quick_menu .q_list section:nth-of-type(1) ul ul>li:first-child").find("a").first().focus();
			}
			if(quickLoc == 1){
				$("#quick_menu .q_list section:nth-of-type(2) ul>li:first-child").find("a").first().focus();
			}
			if(quickLoc == 2){
				$("#quick_menu .q_list section:nth-of-type(3) ul>li:first-child").find("a").first().focus();
			}

			return false;
		}
	});
	$("#quick_menu .q_list section:nth-of-type(1) ul>li:first-child>ul>li:first-child>a").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				$("#quick_menu .q_list .btn_close").focus();
				return false;
			}
		}
	});
	$("#quick_menu .q_list .btn_close").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
	   			$("#quick_menu .q_list section:nth-of-type(3)>ul>li:last-child>ul>li:last-child").find("a").first().focus();
	   			return false;
	   		}else{
	   			$("#quick_menu .q_list section:nth-of-type(1)>ul>li:first-child").find("a").first().focus();
	   			return false;
	   		}
		}
		/*190723수정 시작*/
		if(v_keyCode == 13){
			$("#quick_menu .q_list .btn_close").trigger('click');
			//$("footer .f_menu").find('a').first().focus();
			$("#quick_menu .q_top .btn_menu:nth-of-type(" + (quickLoc+1) + ")").focus();
			return false;
		}
		/*190723수정 끝*/
	});

	$("footer .f_menu li:first-child>a").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				$("#quick_menu .q_top>.btn_menu:nth-of-type(3)").focus();
				return false;
			}
		}
	});
});
