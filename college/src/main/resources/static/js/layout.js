
$(function () {
    var gnb_obj = $("#gnb");
    gnb_obj.li = $("#gnb .dep01 > li");
    gnb_obj.li.a = gnb_obj.li.find(">a");
    gnb_obj.li.ul = $("#gnb .dep02");

    // 페이지 로드시 메인메뉴 2뎁스 중 3뎁스가 있는 메뉴에 class 추가
    $("#gnb .dep02 > li").each(function (index) {
        ($(this).find("ul").length > 0) ? $(this).addClass("child") : "";
        $("#gnb .dep02 > li.child").addClass("active");
        $("#gnb .dep02 > li.child > a").attr("title", "열림");
    });
    /*
    gnb_obj.find(".child > a").on("click", function() {
      return false;
    });*/

    /* 1차메뉴 width setting */
    dep01_Count = gnb_obj.li.length; //1차메뉴 갯수
    if (dep01_Count > 2) {
        gnb_obj.li.css('width', (100 / dep01_Count) + "%");
    }
    //gnb hover시 검색창 비활성화
    /*
    gnb_obj.on("mouseover", function() {
      $("#mSearch").slideUp();
    });*/
    // default & 2차메뉴 체크
    gnb_obj.li.each(function (e) {
        $(this).addClass("num" + (e + 1));

        if ($(this).find('ul > li').length > 0) {
            $(this).addClass("child");
        }
    });
    // keydown시 transition 비활성화
    gnb_obj.on('keydown', function (key) {
        if (key.keyCode == 9) {
            gnb_obj.li.ul.css('transition', 'none');
        }
    })

    /* 2021.02.26. SY,CHo 웹접근성 개선작업 
    $("#gnb .dep02 > li.child > a").attr("title", "닫힘");
    $("#gnb .dep02 > li.child.active > a").attr("title", "열림");
    */

    // 메뉴타입 체크
    if ($('#gnb').hasClass("oneDown")) {
        //하나씩
        oneDown();
    } else {
        fullDown();
    }
    // 메뉴타입 : oneDown
    function oneDown() {
        // OneDown width 
        $('#gnb.oneDown .dep02').wrap('<div class="dep02_wrap"></div>');
        // OneDown text
        $('#gnb.oneDown .dep02').before("<div class='gnb_txt'><strong><em></em></strong><span>Seoul National University <br>of Education</span></div>");
        $("#gnb .dep01 > li").each(function () {
            var dtxtext01 = $(this).children("a").find("span").text();
            $(this).children().find(".gnb_txt em").text(dtxtext01);
            var dep02_Count = $(this).children(".dep02").find(".dep02_wrap > ul > li").length; //2차메뉴 갯수
            var dep02_li = $(this).children(".dep02").find(".dep02_wrap > ul > li");
            if (dep02_Count > 2) {
                dep02_li.css('width', (100 / dep02_Count) + "%");
            }
        });

        // 메인메뉴 2뎁스 높이
        /* 220208 hyerim 불필요한 메뉴 높이 삭제
        $(window).bind('resize', function() {
          function _bgHeight(a) {
            var bgHeight = 0;
            for (var i = 0; i < a.length; i++) {
              bgHeight = Math.max(bgHeight, a.eq(i).find("> .dep02").removeAttr("style").innerHeight());
            }
            $('#gnb .dep02').height(bgHeight);
            $('#gnb .bgMenuBar').height(bgHeight);
          }
          _bgHeight($('#gnb .dep01 > li'));
        }).trigger('resize');
        
        function _bgHeight(a) {
            var bgHeight = 0;
            for (var i = 0; i < a.length; i++) {
              bgHeight = Math.max(bgHeight, a.eq(i).find(".dep02").removeAttr("style").innerHeight());
            }*/
        //console.log(bgHeight);
        /* 220208 hyerim 불필요한 메뉴 높이 삭제
            $('#gnb .dep02').height(bgHeight);
            $('#gnb .bgMenuBar').height(bgHeight);
          }
          _bgHeight($('#gnb .dep01 > li'));*/

        $('#header').on('mouseleave', function () {
            $('#header').removeClass('mainMenuOpen');
            $('#gnb .dep01 > li').removeClass('active');

            //_bgHeight($('#gnb .dep01 > li')); 220208 hyerim 불필요한 메뉴 높이 삭제
        });

        // 메인메뉴
        $('#gnb .dep01 > li > a').on('focusin mouseenter click', function (e) {
            $('#header').addClass('mainMenuOpen');
            $(this).parent().addClass('active').siblings().removeClass('active');
            if ($(this).hasClass('return')) {
                e.preventDefault();
            }

            //검색창이 열려있을때는 메인메뉴 비활성화
            if ($('#header').hasClass('searchOpen')) {
                $('#header').removeClass('mainMenuOpen');
                $('#gnb .dep01 > li').removeClass('active');
            }
        });
        /*
        $('#gnb .dep02 > li.child > a').on('click', function(e) {
          $('#gnb .dep02 > li.child').not($(this).parent("")).removeClass('active');
          $('#gnb .dep02 > li.child').not($(this).parent("")).find('> a').attr("title", "닫힘");
          $(this).parent().toggleClass('active');
          ($(this).parent().hasClass('child active') == true) ? $(this).attr("title", "열림"): $(this).attr("title", "닫힘");
    
          _bgHeight($('#gnb .dep01 > li'));
    
          e.preventDefault();
        });
        */
    }
    // 메뉴타입 : fullDown
    function fullDown() {
        // 메인메뉴 2뎁스 높이
        $(window).bind('resize', function () {
            function _bgHeight(a) {
                var bgHeight = 0;
                for (var i = 0; i < a.length; i++) {
                    bgHeight = Math.max(bgHeight, a.eq(i).find("> .dep02").removeAttr("style").innerHeight());
                }
                $('#gnb .dep02').height(bgHeight);
                $('#gnb .bgMenuBar').height(bgHeight + 30);
            }
            _bgHeight($('#gnb .dep01 > li'));
        }).trigger('resize');

        function _bgHeight(a) {
            var bgHeight = 0;
            for (var i = 0; i < a.length; i++) {
                bgHeight = Math.max(bgHeight, a.eq(i).find("> .dep02").removeAttr("style").innerHeight());
            }
            $('#gnb .dep02').height(bgHeight);
            $('#gnb .bgMenuBar').height(bgHeight + 30);
        }
        _bgHeight($('#gnb .dep01 > li'));

        // 2020.12.11. SY,CHo 메인메뉴 2depth이하 마우스 오버시 해당 1depth 메뉴 활성화
        $('#gnb .dep02').on('mouseenter', function () {
            $('#gnb .dep01 > li').removeClass('active');
            $(this).parent("li").addClass('active');
        });
        $('#gnb .dep01').on('mouseleave', function () {
            $('#header').removeClass('mainMenuOpen');
            $('body').removeClass('quick_menu_active');
            $('#gnb .dep01 li').removeClass('active');
            _bgHeight($('#gnb .dep01 > li'));
        });

        // 메인메뉴
        $('#gnb .dep01 > li > a').on('focusin mouseenter click', function (e) {
            $('#header').addClass('mainMenuOpen');
            $('body').addClass('quick_menu_active');
            $(this).parent().addClass('active').siblings().removeClass('active');
            if ($(this).hasClass('return')) {
                e.preventDefault();
            }
        });
        $('#gnb .dep02 > li.child > a').on('click', function (e) {
            $('#gnb .dep02 > li.child').not($(this).parent("")).removeClass('active');
            $('#gnb .dep02 > li.child').not($(this).parent("")).find('> a').attr("title", "닫힘"); /* 2021.02.26. SY,CHo 웹접근성 개선작업 */
            $(this).parent().toggleClass('active');
            ($(this).parent().hasClass('child active') == true) ? $(this).attr("title", "열림") : $(this).attr("title", "닫힘"); /* 2021.02.26. SY,CHo 웹접근성 개선작업 */
            _bgHeight($('#gnb .dep01 > li'));
            e.preventDefault();
        });
    }

    // 마지막 메뉴에서 focusout시 메뉴 닫기 201203 sehyun oh 추가
    $("#gnb .dep01 [class^='dep'] > li:last > a").on("keydown", menuCloseLastKeydown);
    $("#gnb .dep01 > li > [class^='dep'] > li:last:has([class^='dep']) > a").on("keydown", menuCloseLastKeydown);

    function menuCloseLastKeydown(e) {
        if ($(e.currentTarget).parent("li").hasClass("active")) return;
        if (!e.shiftKey && (e.keyCode || e.which) === 9) {
            $('#header').removeClass('mainMenuOpen');
            $('#gnb .dep01 li').removeClass('active');
        }
    }

    // 사이트맵
    $("#gnb .dep01").clone().prependTo('#popFullmenu .fullmenu_group').find('.dep02').removeAttr('style');
    $("#header .util").clone().prependTo('#popFullmenu .fullmenu_util');


    if ($('.popFullmenu').length > 0) {
        $(".popFullmenu .fullmenu_group").mCustomScrollbar({
            theme: "dark-thick",
            scrollInertia: 200,
        });
    }

    // 모바일 메뉴 클릭이벤트
    $('.popFullmenu a').on('click', function (e) {
        if ($(window).width() <= 1280) {
            if ($(this).parent().hasClass('child') == true) {
                if ($(this).parent().hasClass('active') == true) {
                    $(this).next().find('active').removeClass('active');
                    $(this).parent().removeClass('active');
                } else {
                    $('.popFullmenu li').removeClass('active');
                    $(this).parents('li').addClass('active');
                }
                e.preventDefault();
            }
        }
    });
    // 모바일 오픈메뉴 close처리
    $('#fullmenuClose').on('click', function () {
        $('.popFullmenu li').removeClass('active');
    }).on('focusout', function () {
        $('.fullmenu_wrap .dep01 > li:first-child > a').focus();
    });

    //통합검색 실행 시 퀵메뉴 안보임
    $(".total_search .hash").click(function () {
        $('#header').removeClass('mainMenuOpen');
        $('#gnb .dep01 > li').removeClass('active');

        function _bgHeight(a) {
            var bgHeight = 0;
            for (var i = 0; i < a.length; i++) {
                bgHeight = Math.max(bgHeight, a.eq(i).find(".dep02").removeAttr("style").innerHeight());
            }
            //console.log(bgHeight);
            $('#gnb .dep02').height(bgHeight);
            $('#gnb .bgMenuBar').height(bgHeight);
        }
        _bgHeight($('#gnb .dep01 > li'));

        $('#header').addClass('searchOpen');
    });
    $(".total_search .btnSearchClose").click(function () {
        $('#header').removeClass('searchOpen');
    });
	//페이지이동, 새로고침시 퀵메뉴 유지
	$(document).ready(function() {
		if(null != localStorage.getItem('isHide') && null != localStorage.getItem('isOpen') && localStorage.getItem('isHide') == 'Y' && localStorage.getItem('isOpen') == 'Y'){
			$('#user_open').addClass('hide');
        	$('#user').addClass('open');
		} else {
			$('#user_open').removeClass('hide');
        	$('#user').removeClass('open');
		}
	});
    //유저별 바로가기
    $('#user_open').on('click', function (e) {
        e.preventDefault();
        /*$(this).addClass('hide');
        $('#user').addClass('open');*/
        localStorage.setItem('isHide', 'Y')
        localStorage.setItem('isOpen', 'Y')
        if(null != localStorage.getItem('isHide') && null != localStorage.getItem('isOpen') && localStorage.getItem('isHide') == 'Y' && localStorage.getItem('isOpen') == 'Y'){
			$('#user_open').addClass('hide');
        	$('#user').addClass('open');
		}
    });
    $('#user .close').on('click focusout', function (e) {
        e.preventDefault();
        /*$('#user_open').removeClass('hide');
        $('#user').removeClass('open');*/
        localStorage.setItem('isHide', 'N')
        localStorage.setItem('isOpen', 'N')
        if(null != localStorage.getItem('isHide') && null != localStorage.getItem('isOpen') && localStorage.getItem('isHide') == 'N' && localStorage.getItem('isOpen') == 'N'){
			$('#user_open').removeClass('hide');
        	$('#user').removeClass('open');
		}
    });
	
	

    // 바로가기
    $('#user > ul > li > a').on('click', function (e) {
        $('#user').addClass('active');
        $(this).parent().addClass('active').siblings().removeClass('active');
        e.preventDefault();
    });
    $('#user').on('mouseleave', function (e) {
        $('#user').removeClass('active');
        $('#user').find('.active').removeClass('active');
    });


    // HASH 버튼
    $('.hash').on('click', function (e) {
        $(this.hash).slideDown(100).attr('tabindex', 0).focus();
        e.preventDefault();

        if ($(this).attr('href') === '#popFullmenu') {
            $('html').css('overflow', 'hidden');
        }

        if ($(this).attr('href') === '#popUp') {
            $('html').css('overflow', 'hidden');
        }
    });
    $('.hashClose').on('click', function (e) {
        $(this.hash).slideUp(100);
        e.preventDefault();

        if ($(this).attr('href') === '#mSearch') {
            $('.fullmenu_btn a').focus();
        }

        if ($(this).attr('href') === '#popFullmenu') {
            $('html').css('overflow', '');
            $('#fullmenuOpen').focus();
        }

        if ($(this).attr('href') === '#popUp') {
            $('html').css('overflow', '');
            $('.btnPopup a').focus();
        }
    }).on('focusout', function () {
        if ($(this).attr('href') === '#mSearch') {
            $(this.hash).slideUp(100);
            $('.fullmenu_btn a').focus();
        }
    });

    // HASH TOGGLE 버튼
    $('.hashToggle').on('click', function (e) {
        $(this.hash).slideToggle();
        e.preventDefault();
    });

    // HASH TOGGLE Class버튼
    $('.hashToggleClass').on('click', function (e) {
        $(this.hash).toggleClass('active');
        e.preventDefault();
    });

    $(window).scroll(function () {
        if ($(this).scrollTop() > $(window).height() * 0.3) {
            $('.btnTop').fadeIn();
        } else {
            $('.btnTop').fadeOut();
        }
    });

    //Click event to scroll to top
    //$('.btnTop').click(function () {
    $('#user .top').click(function () {
        $('html, body').animate({ scrollTop: 0 }, 800);
        return false;
    });

    footer(); //footer Site Llink 호출
    snb();

    $("#gnb .dep03 a").wrapInner("<span></span>");
    $("#snb .dep03 a").wrapInner("<span></span>");
});

function TabBox(div, tit) {
    $tab = $('.' + div);

    $tab.find(tit).each(function () {
        $(this).find('a').on("focus click", function (e) {
            e.preventDefault(); //상단이동방지

            $(this).parent(tit).siblings('.list_box').removeClass('on');
            $(this).parent(tit).siblings().find('> a').removeClass('current');
            $(this).parent(tit).next('.list_box').addClass('on');
            $(this).addClass('current');
        });
    });
}


// 서브메뉴  
function snb() {
    var $snb = $('#snb');

    $snb.find('.active:last').parent().addClass('mobSnb');
    $snb.find('.active:last').parents().addClass("active");
    $snb.find('li').each(function () {
        if ($(this).hasClass('active') == true) {
            var active = $(this).clone().removeAttr('id');
            var lnbName = $(this).find('>a>span').clone().text();
            $(this).after(active).next().removeClass('active').find('ul').remove();
            $(this).find('>a').prop('title', lnbName + ' 메뉴 펼치기'); //접근성 : active 메뉴 타이틀 추가
        }
    });
 
    $snb.find('li.active > a').on('click mouseover', function (e) {
        $snb.find('ul').removeClass('open');
        $(this).parent().parent().addClass('open');
        depthCheck = true;
        e.preventDefault();
    });
    $snb.find('ul').on('mouseleave', function () {
        $(this).removeClass('open');
    }); 

    var depthCheck = true;
    $('#snb .dep01 li a, #snb .dep02 li a, #snb .dep03 li a').on('focusout', function (e) {
        if ($(this).parent().parent().hasClass('open')) {

            var activeDepthIdx = $(this).parent().parent().find(".active").index();
            if (activeDepthIdx > 0) {
                if ($(this).parent().index() == 0) {
                    depthCheck = false;
                    if (activeDepthIdx == 1) {
                        $(this).parent().parent().children("li").eq(activeDepthIdx + 1).children().focus();
                    } else {
                        $(this).parent().next().children().focus();
                    }
                } else {
                    if (depthCheck) {
                        $(this).parent().parent().children("li").eq(0).children().focus();
                        console.log(2);
                    } else {
                        console.log(1);
                        if ((activeDepthIdx - 1) == $(this).parent().index()) {
                            $(this).parent().parent().children("li").eq(activeDepthIdx + 1).children().focus();
                        } else {
                            $(this).parent().next().children().focus();
                        }
                    }
                }
            } else {
                $(this).parent().next().children().focus();
            }


            var depthLiSize = $(this).parent().parent().children().length;
            if (activeDepthIdx == depthLiSize - 1) {
                $(this).parent().parent().children("li").eq(activeDepthIdx - 1).addClass("selLastDepth");
            } else {
                $(this).parent().parent().children("li").last().addClass("selLastDepth");
            }


            var selClass = $(this).parent().parent().attr("class");

            var lastDepth = "";


            if (selClass == "dep01 active open") {
                lastDepth = "dep01";
            } else if (selClass == "dep02 active open") {
                lastDepth = "dep02";
            } else {
                lastDepth = "dep03";
            }

            $("." + lastDepth).children(".selLastDepth").on("focusout", function (e) {
                $(this).parent().removeClass('open');
                $(this).parent().children(".active").children("ul").children(".active").children("a").focus();
            });
        }
    });

    // 메뉴영역 외부 클릭 시, 메뉴닫기
    $(document).on('click', function (e) {
        if (!$(e.target).parents().is('#snb')) {
            $('#snb ul').removeClass('open');
        };
    });

    // resize 대응
    var delta = 100;
    var timer = null;
    $(window).on('resize', function () {
        clearTimeout(timer);
        if ($(window).width() > 1024 || $(window).width() < 1024) {
            timer = setTimeout(resizeDone, delta);
        }
    });
    function resizeDone() {
        $('#snb').find('ul').removeClass('open');
    }
}

// snsBox
$(function () {
    var $shareBtn = $('.btnShare'),
        $snsBox = $('.snsBox .sns_more');
    $shareBtnClose = $('.snsBox .btnClose');

    $shareBtn.on("click", function () {
        $(this).toggleClass('open');
        $snsBox.toggle();
        setTimeout(function () {
            $snsBox.find('a:first-child').focus();
        });
        return false;
    });

    $shareBtnClose.on("click focusout", function () {
        $snsBox.hide();
        $shareBtn.removeClass('open');
        return false;
    });
});

//footer Site Llink
function footer() {
    /* 20211202 웹 접근성 수정*/

    $('.footBtn button').click(function () {
        var footBtn = $(this).parent();
        footBtn.siblings().find(">div").slideUp(300);
        footBtn.siblings().removeClass('on');
        footBtn.siblings().find('button').attr('title', '축소됨');

        if (footBtn.hasClass('on')) {
            $(this).next("div").slideUp(300);
            $(this).parent().removeClass('on');
            $(this).attr('title', '축소됨');
        } else {
            $(this).next("div").slideDown(300);
            $(this).parent().addClass('on');
            $(this).attr('title', '확장됨');
        }



        return false;
    });
    $('.footBtnWrap').mouseleave(function () {
        $('.footBtn > div').hide();
        $('.footBtn').removeClass('on');
        $(this).prev().attr('title', '축소됨');
    });
}


//푸터 공유하기 버튼
$(document).ready(function(){
	//페이스북 공유하기    
    $(".btn_facebook").on("click", function(){
        window.open("https://www.facebook.com/sharer/sharer.php?u=" + encodeURIComponent(window.location.href), "_blank", "width=600,height=400");
    });
    //트위터 공유하기
    $(".btn_twitter").on("click", function(){
        window.open("https://twitter.com/intent/tweet?url=" + encodeURIComponent(window.location.href), "_blank", "width=600,height=400");
    });
    //블로그 공유하기
    $(".btn_blog").on("click", function(){
      var url = encodeURI(encodeURIComponent(window.location.href));
      var title = encodeURI(window.location.href);
      window.open("https://share.naver.com/web/shareView?url=" + url + "&title=" + title, "_blank" , "width=600,height=400");
      
    });
});