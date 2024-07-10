$(document).ready(function(){
	// var img_src = "../images/"; //update img_src;
	
	// slider
	var slides = $('#slides');
	var cslide = slides.clone().removeAttr('id').addClass('clone c1');
	cslide.children(':last').prependTo(cslide);
	cslide.find('.obj').remove();
	slides.after(cslide);
	cslide = slides.clone().removeAttr('id').addClass('clone c2');
	cslide.children(':first-child').appendTo(cslide);
	cslide.find('.obj').remove();
	slides.after(cslide);
	$('.slides').each(function(){
		var options = {
			width: 731,
			height: 500,
			play: {
				active: true,
				auto: true,
				interval: 15000,
				swap: true,
				restartDelay: 1000
			},
			pagination:{
				active: false
			}
		};
		if ($(this).is('#slides')){
			options.callback = {
				loaded:function(n){
					var img = slides.find('.slidesjs-slide').eq(n-1).find('img:first-child');
					slides.siblings('.caption').find('.txt').html(img.prop('alt'));
					img.siblings('.obj').animate({bottom:90})
				},
				complete:function(n){
					var img = slides.find('.slidesjs-slide').eq(n-1).find('img:first-child');
					slides.siblings('.caption').find('.txt').html(img.prop('alt')).fadeIn();
					img.siblings('.obj').animate({bottom:90})
					slides.find('.slidesjs-slide').find('img.obj').not(img).css({bottom:70});
				},
				start:function(n){
					slides.siblings('.caption').find('.txt').hide();
				}
			}
		}
		$(this).slidesjs(options);
	});
	
	var tt = null;
	slides.on('click','.slidesjs-previous',function(e){
		e.preventDefault();
		slides.siblings('.slides').find('.slidesjs-previous').click();
		clearInterval(tt);
		tt = setTimeout(function(){
			slides.find('.slidesjs-play').click();
		},100);
	}).on('click','.slidesjs-next',function(e){
		e.preventDefault();
		slides.siblings('.slides').find('.slidesjs-next').click();
		clearInterval(tt);
		tt = setTimeout(function(){
			slides.find('.slidesjs-play').click();
		},100);
	}).on('click','.slidesjs-play',function(e){
		e.preventDefault();
		slides.siblings('.slides').find('.slidesjs-play').click();
	}).on('click','.slidesjs-stop',function(e){
		e.preventDefault();
		slides.siblings('.slides').find('.slidesjs-stop').click();
	});
	
	// boards
	$('.boards').on('click','.btn-boards a',function(e){
		e.preventDefault();
		var brd = $(this).closest('.boards');
		if(brd.height()==35) {
			brd.animate({height:169},200);
		} else {
			brd.animate({height:35},200);
		};
		brd.find('.top,.bottom').toggle();
		fnBoard('1', '1', '');
		fnBoard('2', '1', '');
		fnBoard('3', '1', '');
	}).on('click','.top .btns a.prev',function(e){
		e.preventDefault();
		var current = $(this).closest('.btns').siblings('ul').children(':visible');
		if (current.prev().length)
			current.removeClass('on').prev().addClass('on');
		else
			current.removeClass('on').siblings(':last').addClass('on');
	}).on('click','.top .btns a.next',function(e){
		e.preventDefault();
		var current = $(this).closest('.btns').siblings('ul').children(':visible');
		if (current.next().length)
			current.removeClass('on').next().addClass('on');
		else
			current.removeClass('on').siblings(':first').addClass('on');
	});
	
	$('.quickmenu .ttip').each(function(){
		var tip = $(this);
		tip.tooltip({
			position: {
				my: 'right-20 top-24',
				collision: 'fit',
				of : tip
			}
		});
	});
	
	$(window).on('resize', function(){
		if($(this).width() > 1180){
			$('#quick').addClass('open').attr('style', '')
			   .find('.btnscroll').addClass('on')
			   .siblings('.btntop').addClass('on')
			   .siblings('ul').attr('style', '')
			   .children('li').find('span:nth-child(2)').show();
		} else {
			$('#quick').removeClass('open').attr('style', '')
				.find('.btnscroll').addClass('on')
				.siblings('.btntop').addClass('on')
				.siblings('ul').attr('style', '')
				.children('li').find('span:nth-child(2)').hide();
		}
		if($('.layerpop').length > 0){
			$('.layerpop').dialog('option', 'position', 'center');
		}
		
	}).on('scroll', function(){
		/*
		if($('.layerpop').length > 0){
			$('.layerpop').dialog('option', 'position', 'center');
		}
		*/
	});
	
	if($( ".mbtn,.btnui" ).length > 0){
		$(".mbtn,.btnui").button();
	}
	
	/* button corner for IE 8 */
	if(window.PIE){
		$('.mbtn').each(function(){
			PIE.attach(this);
		});
	}
	$('.mbtn.ui-corner-all,.btnui.ui-corner-all').removeClass('.ui-corner-all');
	
	if($('.calendar').length > 0) {
		//var img_src = "/images";
		$( ".calendar" ).datepicker({
			  showOn: "button",
			  buttonImage: img_src + "/new/icon/icon_calendar.png",
			  buttonImageOnly: true,
			  dateFormat: "yy-mm-dd"
		});
	}
	/* Adjust height of left */
	var content_height = $('#container >.wrapper >#contents').height() + 124;
	if($('#left2').height() < content_height){
		$('#left2').css({
			'height': content_height +'px',
			'padding-bottom': '0'
		});
	}
	/* Adjust frame height */
	//$('.frame').css('height', parseInt($('#left').height()-18)+'px');
	/* Family Site */
	$('.family_site>li').on('click', '>a', function(){
		if($(this).siblings('.submenu').is(':visible')){
		  $(this).siblings('.submenu').hide();
		  $(this).siblings('.submenu').siblings('a').removeClass('on');
		} else {
			var tab = $(this).siblings('.submenu').find('.tabs');
		  $('.family_site>li .submenu').hide();
		  $('.family_site>li>a').removeClass('on');
		  $(this).addClass('on');
		  $(this).siblings('.submenu').show();
		  $(this).siblings('.submenu').find('.tab_content').hide();
		  tab.children('li').removeClass('on')
		  tab.children('li:first-child').addClass('on');
		  $(this).siblings('.submenu').find('.tab_content.first').show();
		}
	});
	$('.family_site>li:first-child>a').on('focus',function(){
		$('.main_menu>ul>li:last-child>div').hide();
	});
	$('.submenu .tabs li').on('click', function(){
		$(this).addClass('on').siblings('li').removeClass('on');
		$('.tab_content').hide();
		$(this).children('.tab_content').show();
	});
	$('.submenu .fclose').on('click', function(){
		$(this).closest('.submenu').hide();
		$(this).closest('.submenu').siblings('a').removeClass('on');
	});
	
	/* Utility (User and Language) */
	$('.utility>li.user').on('click','>a', function(){
		if($(this).siblings('div').is(':visible')){
			$(this).removeClass('on');
			$(this).siblings('div').hide();
		} else {
			$(this).addClass('on');
			$(this).siblings('div').show();
		}
	});
	$('.userclose').on('click', function(){
		$(this).closest('li').find('>a').removeClass('on');
		$(this).closest('li').find('>div').hide();
	});
	$('.utility>li.lang').on('mouseover focus','>a',function(){
		$(this).addClass('on');
		$(this).siblings('div').show();
	}).on('mouseleave', function(){
		$(this).find('>a').removeClass('on');
		$(this).find('>div').hide();
	});
	/* Header 2 Utility (User and Language) */
	$('.utility2 >li.user,.utility2 >li.lang').on('mouseover focus', '>a', function(){
		$(this).addClass('on').siblings('div').show();
	}).on('mouseleave', function(){
		$(this).find('>a').removeClass('on').siblings('div').hide();
	});
	
	/* Main Menu 1 */
	var menu_cnt = $('.menus>li').length;
	$('.menus>li').each(function() {
		$(this).css('width', parseInt((876-menu_cnt) / menu_cnt) +'px');
	});
	$('.main_menu .fullmenu').on('mouseover focus','>a', function(){
		$(this).siblings('ul').show();
		$(this).addClass('on');
	}).on('mouseleave', function(){
		$(this).children('ul').hide();
		$(this).find('>a').removeClass('on');
	});
	$('.fullmenu ul li').on('click', '>a', function(){
		var cls = $(this).attr('id');
		$('.main_menu >ul').hide();
		$('.main_menu >ul.'+cls).show();
		$(this).closest('ul').siblings('a').text($(this).text());
	})

	$('.msub >a').on('mouseover focus', function(){
		$(this).prevAll('.grp_title:first').addClass('on');
	}).on('mouseleave', function(){
		$(this).prevAll('.grp_title:first').removeClass('on');
	});
	
	var menu_cnt = $('.main_menu .menus >li').length,
		menu_len = parseInt((776-menu_cnt)/menu_cnt);

	$('.main_menu>ul>li').on('mouseover focus', '>a',function(){
		$('.msub').hide();
		$('.main_menu>ul>li').removeClass('on');
		$('.main_menu>ul>li.fullmenu ul').hide();

		$(this).parent().addClass('on').find('>a').removeClass('active');
		$(this).siblings('.msub').show();
		
		/* Too many submenu */
		var menucnt = $(this).siblings('.msub').find('>a').length,
			titlecnt = $(this).siblings('.msub').children('.grp_title').length * 2;
		//if(parseInt(menucnt+titlecnt) > 75){
			$(this).siblings('.msub').addClass('long');
		//}
		/* remove line of next menu */
		if($(this).siblings('.msub').length > 0){
			$(this).closest('ul').find('li.nobg').removeClass('nobg');
			$(this).parent().next().addClass('nobg');
		} else {
			$(this).css('border-bottom', '0');
		}

		var target = $(this).siblings('.msub');
		
		if(target.length == 0){
			$(this).parent().css({
				'height': '35px',
				'border-color': '#fff',
				'border-bottom': 'none'
			});
			$(this).css({
				height: '24px',
				background: 'none'
			});
		}
		if(target.children('div').length == 0){
			var obj,len,newwid,pos,mod=26,
			language = "ko"; //modify for value of language
			cnt = 1,start = 1,tot=0;
			
			mod = (language == 'ko' ? 20 : 20);
		

		  	target.children('a,.grp_title').each(function(){
		  		
			  if($(this).is("span")){
				  for(var i=1;i<3;i++){
					  if(cnt%mod === 0){
						  tot = tot+1;
						  obj = target.children(':nth-child('+start+')').nextUntil($(this));
						  obj.wrapAll("<div></div>");
						  start = $(this).index();
					  }
					 cnt = cnt+1;
				  }
			  } else {
				  if(cnt%mod === 0){
					  tot = tot+1;
					  obj = target.children(':nth-child('+start+')').nextUntil($(this));
					  obj.wrapAll("<div></div>");
					  start = $(this).index();
				  }
				  cnt++;
			  }
		  	});
		  	len = target.find('.grp_title,a').length;
		  	
		  	/* Remaining links, place it inside a div */
		  	var out = target.children('div:nth-child('+tot+')').next();
		  	
			if(out.length > 0){
				tot += 1;
				nobj = out.nextAll();
				nobj.wrapAll("<div></div>");
			}
		
			if(tot == 0){
				newwid = 165;
				target.css('padding-bottom', '10px');
			} else {
				newwid = tot * 165+(tot-1);
			}
			pos = $(this).parent("li").position().left;
			diff = parseInt(873 - pos);
			target.css('width',newwid+'px');

			
			// Adjust position of dropdown if will overflow from menu 
			if(newwid > diff){
				target.css('left',parseInt(newwid-diff)*(-1)+'px');
			}
		}
		
		/* If menu width is > 165 and submenu has only 1 column */
		var par_width = $(this).parent().width();
		if( (par_width > 165) && (target.children('div').length == 1)){
			$(this).parent().css('width', par_width);
			$(target).css({
				width: par_width + 'px',
				background: '#fff'
			});
		}
		$(this).siblings('.pointer').show();
	}).on('mouseleave', function(){
		$(this).removeClass('on');
		$(this).next().removeClass('nobg');
		$(this).children('.msub').hide().siblings('.pointer').hide();
	});
	
	/* Main Menu 2 */
	/* Menu 2 Group Select */
	$('.dropdown >a').on('click', function(){
		if($(this).siblings('div').is(':visible')){
			$(this).removeClass('on').siblings('div').slideUp();
		} else {
			$(this).addClass('on').siblings('div').slideDown();
		}
	});
	$('.fmenu2 >ul >li >a').on('click', function(){
		$(this).parent('div').siblings('a').text($(this).text());
		$(this).parent('div').hide();
		
		$('.main_menu >ul').hide();
		
		if($(this).text() == "교원메뉴"){
			$('.main_menu >ul.teachers').show();
		} else if($(this).text().indexOf('복합교직원메뉴복') >= 0){
			$('.main_menu >ul.staff').show();
		} else {
			$('.main_menu >ul.student').show();
		}
	});
	
	/* Search input default value */
	$('.iptsearch').focus(function(){
		//var language = 'ko'; //modify language
		if(this.value == (language == 'ko' ? "검색어를 입력하세요." : "Input Search Keywords.")){
			$(this).val("");
		}
	}).blur(function(){
		//var language = 'ko'; //modify language
		if(this.value == ""){
			$(this).val(language == 'ko' ? "검색어를 입력하세요." : "Input Search Keywords.");
		}
	});
	
	$('h1 a').on('focus', function(){
		$('.utility>li.lang>div').hide();
	});

	$('.grp_title').prev('a').each(function(){
		$(this).addClass('last');
	});
	
	$('.menus').hide();
	$('.menus').show();
	
	/* Quick Menu */
	if($(window).width() > 1024){
		$('#quick').addClass('open').children('.btnscroll').addClass('on');
		if($('.quickmenu .ttip').length > 0){
			$('.quickmenu .ttip').tooltip("disable");
		}
	}
	$('.btnscroll').click(function(){
		if($(this).hasClass('on')){
			closeQuickM();
			$('.quickmenu .ttip').tooltip("enable");
		} else {
			openQuickM();
			$('.quickmenu .ttip').tooltip("disable");
		}
	});
	$('#btnqfave').on('click', function(){
		$(this).siblings('div').fadeIn(500);
	});
	$('#btnfaveclose').click(function(){
		$(this).closest('.qfavorite').fadeOut(500);
	});
	
	/* Left Menu */
	$('.leftmenu>li>a').on('click', function(e){
		var li = $(this).parent('li');
		
		if(li.hasClass('on')){
			li.removeClass('on');
			li.children('ul').hide();
		} else {
			li.siblings('li.on').removeClass('on');
			$('.leftmenu>li>ul').hide();
			li.addClass('on');
			li.children('ul').show();
		}
	});
	$('#checkAll').click(function(){
		if($(this).prop("checked")){
			$(this).closest('table').find('tr').children('td:first-child').children('input[type=checkbox]').prop('checked', true);	
		} else {
			$(this).closest('table').find('tr').children('td:first-child').children('input[type=checkbox]').prop('checked', false);	
		}
	});
	
	$('.stabs li').click(function(){
		var on = $(this).siblings('.on'),
		   idx = $(this).index()+1,
		   tabc = $(this).closest('.stop').next('.stab_content');
		
		$(this).next('li').children('a').css('border-color', '#bfbebe');
		$(this).addClass('on');
		on.removeClass('on').children('a').css('border-color', '#cdc9cf');

		tabc.find('>div').hide();
		tabc.find('>div:nth-child('+idx+')').show();
	});

	$('.box_tabs li').click(function(e){
		e.preventDefault();
		var box_content = $(this).closest('.box_top').siblings('.box_content');

		$(this).addClass('on').siblings('.on').removeClass('on');
		$(this).prev().css('border-right-color', '#ccccce');
		//box_content.children('.box_tab_content').hide();
		//box_content.children('.box_tab_content:nth-child('+ ($(this).index()+1) +')').show();
	});
	$('.box_tab_content .nav a').click(function(e){
		e.preventDefault();
		var list = $(this).closest('.nav').siblings('ul:visible');

		if($(this).hasClass('next')){
			if(list.next().length > 0){
				$(this).siblings('span').children('span').text(list.index()+1);
				list.hide().next('ul').show();
			}
		} else {
			if(list.prev().length > 0 && list.index() > 1){
				$(this).siblings('span').children('span').text(list.index() -1);
				list.hide().prev('ul').show();
			}
		}
	});
	
	$('.portlet .ptab li').click(function(){	
		$(this).addClass('on').siblings('.on').removeClass('on');
	});
	
	$('.section_tabs li').click(function(){
		var sec_cont = $(this).closest('.section_top').siblings('.section_content');
		
		$(this).addClass('on').siblings('.on').removeClass('on');
		sec_cont.children('.section_tab_content').hide();
		sec_cont.children('.section_tab_content:nth-child('+($(this).index()+1)+')').show();
	});
	
	$('.bt_tab li, .login_bbtns li').click(function(){
		var on = $(this).siblings('.on'),
		   idx = $(this).index() + 1,
		   tabc = ($(this).parent().attr('class') == "bt_tab") ? $(this).closest('.box_top').next('.tab_content') : $(this).closest('.board_top').next('.tab_content');

		$(this).addClass('on').siblings('.on').removeClass('on');
		
		tabc.children('div').hide();
		tabc.children('div:nth-child('+idx+')').show();
	});
	
	$('.tabtop ul li').click(function(){
		var idx = $(this).index()+1;
		
		$(this).addClass('on').siblings('.on').removeClass('on');	
		$(this).closest('.tabtop').siblings('.tabgroup_content').children().hide();
		$(this).closest('.tabtop').siblings('.tabgroup_content').children('div:nth-child('+idx+')').show();
		
		if(idx == 2){
			$(this).closest('#quicklink').addClass('visual2');	
		} else if(idx == 3){
			$(this).closest('#quicklink').addClass('visual3');	
			$('#quicklink').find('.group1').hide();
			$('#quicklink').find('.group2').show();
		} else {
			$(this).closest('#quicklink').attr('class', '');
		}
	});
	
	$('.tt_top div ul li').click(function(){
		$(this).addClass('on').siblings('.on').removeClass('on');
	});
	
	$('.visual .tabs ul li').click(function(){
		var idx = $(this).index()+1, cls="";
		
		$(this).siblings('.on').removeClass('on');
		$(this).addClass('on');
		
		if(idx == 1) cls = "student";
		else if(idx == 2) cls = "staff";
		else cls = "campus";
		
		$('#quicklink.'+cls).show().siblings('#quicklink').hide();
		$('#quicklink.'+cls).find('.tabs ul li:nth-child('+idx+')').addClass('on').siblings('li').removeClass('on');
	});
	$('#campus_close').click(function(){
		$('#quicklink').removeClass('visual3').find('.group1').show().find('.group2').hide();
		$('#quicklink').find('.tabtop ul li:first-child').addClass('on').siblings('li').removeClass('on');
		$('#quicklink').find('.tabgroup_tab_content:first-child').show().siblings().hide();
		$('#quicklink').attr('class', '');
	});
	$('.vbtns li a').hover(function(){
		var img = $(this).parent().find('img');
		$(this).parent().addClass('on');
		img.attr('src',img.attr('src').replace('_off', '_on'));
	}, function(){
		var img = $(this).parent().find('img');
		$(this).parent().removeClass('on');
		img.attr('src', img.attr('src').replace('_on', '_off'));
	});

	$('.ql_tabs >li >a').click(function(){
		$(this).parent().siblings('.on').removeClass('on');
		$(this).parent().addClass('on');
	});
	
	var qtabs_cont = $('.ql_tabs-cont>div').hide()
	qtabs_cont.eq($('.ql_tabs2 >li.on').index()).show();
	$('.ql_tabs2 >li >a').click(function(){
		var menu_item = $(this).parent();
		menu_item.addClass('on').siblings().removeClass('on');
		qtabs_cont.eq(menu_item.index()).show().siblings().hide()
	});
	
	if($('.layerpop').length > 0){
		$('.layerpop').dialog({
			width: 820,
			dialogClass: 'layer_dialog',
			position: 'center',
			autoOpen: false,
			modal: true,
			focus: function(event, ui) {
			    $(this).parent().css('position', 'fixed');
			    $(this).parent().css('z-index', '9999999');
			}
		});
	}
	if($('.loginpop').length > 0){
		$('.loginpop').dialog({
			width: 410,
			dialogClass: 'layer_dialog_login',
			position: 'center',
			autoOpen: false,
			modal: true,
			focus: function(event, ui) {
				$(this).parent().css('position', 'fixed');
				$(this).parent().css('z-index', '9999999');
			}
		});
	}
	if($('.easlayer').length > 0){
		$('.easlayer').dialog({
			width: 410,
			height: 570,
			dialogClass: 'layer_dialog_eas',
			autoOpen: false,
			modal: false,
			resizable:false,
			focus: function(event, ui) {
				$(this).parent().css('margin-right', 'auto');
				$(this).parent().css('margin-left', 'auto');
				$(this).parent().css('z-index', '9999999');
			}
		});
	}
	
	$(".ui-dialog-titlebar").remove();
	$('.dialog_close').click(function(){
		$(this).closest('.layerpop').dialog('close');
		$(this).closest('.loginpop').dialog('close');
		$(this).closest('.easlayer').dialog('close');
	});
 
	/* Search input default value */
	$('.tbl_search .iptsearch').focus(function(){
		var def_value = this.value;
		if(def_value == "검색어를 입력하세요.")
			$(this).val('');
		if(def_value == "Input Search Keyword.")
			$(this).val('');
	}).blur(function(){
		if(this.value == '')
			this.value = ('ko' == language ? "검색어를 입력하세요." : "Input Search Keyword.");
	});
	
	$('#mw').click(function(){
		if($('.smw').is(':visible')){
			$('.smw').hide();
			$(this).removeClass('on');
		} else {
			$('.smw').show();
			$(this).addClass('on');
		}
	});
	$('.smw_top a').click(function(){
		$('#mw').removeClass('on');
		$(this).closest('.smw').hide();
	});
	
	$('.mwidget').on('click', function(){
		$(this).toggleClass('open')
	});
	
	/* Switch on/off */
	$('.section_top .switch a').on('click', function(e){
		e.preventDefault();
		$(this).addClass('current').siblings().removeClass('current');
	});
	
	$('.section_content .nav .up').on('click', function(){
		if($(this).parent().siblings('.list').is(':visible')){
			$(this).addClass('down');
			$(this).parent().siblings('.list').hide();
		} else {
			$(this).removeClass('down');
			$(this).parent().siblings('.list').show();
		}
	});
	
	$('.gtabs li').on('click', function(e){
		e.preventDefault();
		$(this).addClass('on').siblings('.on').removeClass('on');
		$(this).prev().addClass('prev').siblings('.prev').removeClass('prev');
	});
	
	$('.maincampus').on('click', function(){
		if($('.ql_box').is(':visible')){
			$('.ql_box').slideUp();
			$(this).removeClass('on');
		} else {
			$('.ql_box').slideDown();
			$(this).addClass('on');
		}
	});
	
	$('#fullmenu_close').on('click', function(){
		$('.ql_box').slideUp();
		$('.maincampus').removeClass('on');
	});
	
	$('.ql_box2').css({top:'-=10px'})
	$('.sitemap').on('click', function(){
		if($('.ql_box2').is(':visible')){
			$('.ql_box2').animate({top:'-=10px'}).fadeOut({ queue: false});
			$(this).removeClass('on');
		} else {
			$('.ql_box2').fadeIn().animate({top:'+=10px'},{ queue: false});
			$(this).addClass('on');
		}
	});
	
	$('.ql_box2 #fullmenu_close').on('click', function(){
		$('.sitemap').click();
	});
	
	$('.timetable_drop').on('click', function(e){
		e.preventDefault();
		if($(this).hasClass('on')){
			$(this).siblings('.payment_list').children('.hide').hide();
			$(this).removeClass('on');
		} else {
			$(this).siblings('.payment_list').children('.hide').show();
			$(this).addClass('on');
		}
	});
	
	$('.btnfasts').on('click', function(e){
		e.preventDefault();
		if($(this).hasClass('on')){
			$(this).parent().siblings('.box_content').slideUp();
			$(this).removeClass('on');
		} else {
			$(this).parent().siblings('.box_content').slideDown();
			$(this).addClass('on');
		}
	});
	
	$('.hotlinks ul li').on('mouseover', function(){
		var img = $(this).find('>a >span img');
		img.attr('src', img.attr('src').replace('_off', '_on'));
		$(this).addClass('on');
	}).on('mouseleave', function(){
		var img = $(this).find('>a >span img');
		img.attr('src', img.attr('src').replace('_on', '_off'));
		$(this).removeClass('on');
	});
	
	/* Helper Left Menu */
	$('.hleft_menu >li').on('click', function(){
		$(this).addClass('on').siblings('.on').removeClass('on');
		$(this).siblings().children('ul').hide();
		if($(this).children('ul').length > 0){
			$(this).children('ul').slideDown(500);
		}
	})
	/*
	var t = setInterval(function() {
		$('.frame').css('height', $('.frame').contents().find('body').prop('scrollHeight'));
	}, 1000)
	*/
});

openQuickM = function(){
	var btn = $('.btnscroll');
	
	btn.addClass('on');
	$('#quick>ul').css('width','125px');
	$('#quick>ul>li>a span:nth-child(2)').show();
	$('#quick').children('.btntop').addClass('on');
	$('#quick').animate({"width": '135px'}, 500);
};

closeQuickM = function(){
	var btn = $('.btnscroll');
	btn.removeClass('on');
	$('#quick').children('.btntop').removeClass('on');
	$('#quick').animate({"width": '45px'}, 500, function(){
		$('#quick>ul>li>a span:nth-child(2)').hide();
		$('#quick>ul').css('width','35px');
		$('#quick').removeClass('open');
	});
};

doUserType = function(o){
	$(o).closest('form').submit();
};

mainCampus = function() {
	if($('.ql_box').is(':visible')){
		$('.ql_box').slideUp();
	} else {
		$('.ql_box').slideDown();
	}
};

setFAMail = function() {
	/* Switch on/off */
	$('.section_top .switch a').on('click', function(e){
		e.preventDefault();
		if ($(this).hasClass('on')) {
			if(!confirm(language == 'ko' ? '경조사를 메일로 받으시겠습니까?' : 'Would you like to receive email to Funeral/Auspicious Occasion?')) {
				return ;
			}
		}
		
		$(this).addClass('current').siblings().removeClass('current');
		
		$.ajax({
			url : '/common/User/UpdateFAMail.kpd',
			type : 'post',
			data : 'yn=' + ($(this).hasClass('on') ? 'Y' : 'N'),
			dataType : 'html'
		});
	});
};