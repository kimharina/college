(function(){
	TControl = window.TControl = null; 
		
	var options = {
		domain:null
		,url:('https:' == document.location.protocol ? 'https://' : 'http://') + "univ2.uway.com/tcontrol/tconx.php"
		,timeout:3
		,maxInterval:30
		,cookie:"_TControl_KEY_"
		,ttl:3
	};
	
	var state = {
		bypass:false	//bypass 설정 (bypass : true, default : false)
		,type:null
		,url:null
		,target:null
		,fn:null
		,maxWaitCnt:null
		,nowWaitCnt:null
		,state:null
		,key:null
		,use:false
		,waittimeMin:null
		,waittimeSec:null
	};
	
	var stateElem = {
		absoluteDiv:null
		,bgDiv:null
		,stateDiv:null
		,title:null
		,closeBtn:null
		,stateText:null
		,progressBar:null
		,waittime:null
	};
	
	var timerId = null;
	var jsonpTimeout = null;
	var jsonpTimeoutCnt = 0;
	
	var TControlFn = {
		init:function(){
			options.domain = TControlFn.getDomain();

			//20230703 서울여대 티컨 bypass
			if(options.domain  == 'admission.swu.ac.kr') {
				state.bypass = true;
			}
			
			for(var i in TControlFn){
				if(i == "init") continue;
				this[i] = TControlFn[i];
			}

			this.domReady(function(){
				stateElem.absoluteDiv = document.createElement("DIV");
				stateElem.absoluteDiv.style.height = "100%";
				stateElem.absoluteDiv.style.width = "100%";
				stateElem.absoluteDiv.style.position = "absolute";
				stateElem.absoluteDiv.style.left = "0px";
				stateElem.absoluteDiv.style.top = "0px";
				stateElem.absoluteDiv.style.zIndex = "";
				stateElem.absoluteDiv.style.display = "none";

				stateElem.bgDiv = document.createElement("DIV");
				stateElem.bgDiv.style.display = "none";
				stateElem.bgDiv.style.position = "fixed";
				stateElem.bgDiv.style.top = "0px";
				stateElem.bgDiv.style.left = "0px";
				stateElem.bgDiv.style.zIndex = "-5000";
				stateElem.bgDiv.style.width = "100%";
				stateElem.bgDiv.style.height = "100%";
				stateElem.bgDiv.style.background = "#f2f2f2";
				stateElem.bgDiv.style.opacity = "0.4";
				stateElem.bgDiv.style.filter = "alpha(opacity=40);";
				document.body.appendChild(stateElem.bgDiv);
				
				stateElem.stateDiv = document.createElement("DIV");
				stateElem.stateDiv.style.position = "absolute";
				stateElem.stateDiv.style.left = "40%";
				stateElem.stateDiv.style.top = "160px";
				stateElem.stateDiv.style.display = "none";
				stateElem.stateDiv.style.zIndex = "10000";
				stateElem.stateDiv.style.width = "400px";
				stateElem.stateDiv.style.height = "370px";
				stateElem.stateDiv.style.background = "#06334e";
				stateElem.stateDiv.style.borderRadius = "7px";
				document.body.appendChild(stateElem.stateDiv);
								
				var positionDiv = document.createElement("DIV");
				positionDiv.style.position = "relative";
				positionDiv.style.width = "0px";
				positionDiv.style.height = "0px";
				stateElem.stateDiv.appendChild(positionDiv);
				
				stateElem.title = document.createElement("DIV");
				stateElem.title.style.letterSpacing = "-2px";
				stateElem.title.style.textAlign = "center";
				stateElem.title.style.position = "absolute";
				stateElem.title.style.left = "50%";
				stateElem.title.style.top = "50px";
				stateElem.title.style.width = "400px";
				stateElem.title.style.height = "30px";
				stateElem.title.style.color = "white";
				stateElem.title.style.zIndex = "10001";
				stateElem.title.style.font = "27px \"Malgun Gothic\", \"맑은 고딕\"";
				stateElem.title.innerHTML="사이트 접속대기 진행중<br /><span style=\"font-size:19px; color:#55c0ff; letter-spacing:2px;\">Please wait...</span>";
				positionDiv.appendChild(stateElem.title);

				function titleMsgChange(){
					setTimeout(titleMsgChange,1000);
					
					if(!state.use){
						return;
					}
					
					msg = "사이트 접속대기 진행중<br /><span style=\"font-size:19px; color:#55c0ff; letter-spacing:2px;\">Please wait";
					if(!stateElem.title.num){
						stateElem.title.num = 2;
					}
					stateElem.title.num++;
					
					for(i=3-stateElem.title.num%3,m=4;i<m;i++){
						msg += ".";
					}
					msg += "</span>";
					stateElem.title.innerHTML = msg;
				}
				
				setTimeout(titleMsgChange,1000);
				
				var titleLine = document.createElement("DIV");
				titleLine.style.position = "absolute";
				titleLine.style.left = "43px";
				titleLine.style.top = "140px";
				titleLine.style.width = "315px";
				titleLine.style.borderBottom = "1px solid #ffffff";
				positionDiv.appendChild(titleLine);

				var infoText = document.createElement("DIV");
				infoText.style.letterSpacing = "-0.5px";
				infoText.style.color = "#ffffff";
				infoText.style.textAlign = "center";
				infoText.style.position = "absolute";
				infoText.style.left = "0px";
				infoText.style.top = "290px";
				infoText.style.zIndex = "10002";
				infoText.style.width = "400px";
				infoText.style.font = "13px \"Malgun Gothic\", \"맑은 고딕\"";
				infoText.style.lineHeight = "23px";
				infoText.innerHTML="접속중 입니다. 잠시만 기다려 주세요.<br>이 창을 닫으시면 다시 처음부터 대기하셔야 합니다.";
				positionDiv.appendChild(infoText);

				stateElem.closeBtn = document.createElement("DIV");
				stateElem.closeBtn.style.position = "absolute";
				stateElem.closeBtn.style.left = "380px";
				stateElem.closeBtn.style.top = "5px";
				stateElem.closeBtn.style.color = "white";
				stateElem.closeBtn.style.font = "18px \"Malgun Gothic\", \"맑은 고딕\"";
				stateElem.closeBtn.style.zIndex = "10002";
				stateElem.closeBtn.style.cursor = "pointer";
				stateElem.closeBtn.innerHTML="X";
				positionDiv.appendChild(stateElem.closeBtn);

				stateElem.closeBtn.onclick = function(){
					TControlFn.setWaitBox(false);
				};

				stateElem.stateText = document.createElement("DIV");
				stateElem.stateText.style.position = "absolute";
				stateElem.stateText.style.width = "400px";
				stateElem.stateText.style.textAlign = "center";
				stateElem.stateText.style.left = "0px";
				stateElem.stateText.style.top = "230px";
				stateElem.stateText.style.color = "#ffffff";
				stateElem.stateText.style.font = "15px \"Malgun Gothic\", \"맑은 고딕\"";
				stateElem.stateText.style.zIndex = "10002";
				stateElem.stateText.innerHTML="0 / 10000";
				positionDiv.appendChild(stateElem.stateText);

				stateElem.waittime = document.createElement("DIV");
				stateElem.waittime.style.position = "absolute";
				stateElem.waittime.style.width = "400px";
				stateElem.waittime.style.textAlign = "center";
				stateElem.waittime.style.left = "0px";
				stateElem.waittime.style.top = "260px";
				stateElem.waittime.style.color = "#ffffff";
				stateElem.waittime.style.font = "13px \"Malgun Gothic\", \"맑은 고딕\"";
				stateElem.waittime.style.zIndex = "10002";
				stateElem.waittime.innerHTML="";
				positionDiv.appendChild(stateElem.waittime);
				
				var progressbar = document.createElement("DIV");
				progressbar.style.position = "absolute";
				progressbar.style.left = "57px";
				progressbar.style.top = "183px";
				progressbar.style.textAlign = "left";
				progressbar.style.overflow = "hidden";
				progressbar.style.border = "1px solid #aaaaaa";
				progressbar.style.borderRadius = "27px";
				progressbar.style.background = "#ffffff";
				progressbar.style.margin = "-1px";
				progressbar.style.width = "287px";
				progressbar.style.height = "28px";
				progressbar.style.font = "13px \"Malgun Gothic\", \"맑은 고딕\"";
				progressbar.style.zIndex = "10002";

				stateElem.progressBar = document.createElement("DIV");
				stateElem.progressBar.style.margin = "-1px";
				stateElem.progressBar.style.width = "37%";
				stateElem.progressBar.style.height = "100%";
				stateElem.progressBar.style.border = "1px solid #aaaaaa";
				stateElem.progressBar.style.background = "#55c0ff";
				stateElem.progressBar.style.zIndex = "10002";
				progressbar.appendChild(stateElem.progressBar);
				positionDiv.appendChild(progressbar);
								
				stateElem.absoluteDiv.appendChild(stateElem.bgDiv);
				stateElem.absoluteDiv.appendChild(stateElem.stateDiv);

				document.body.insertBefore(stateElem.absoluteDiv,document.body.firstChild);

				if(state.bypass){
					//bypass 설정시 동작안함
				} else {
					if(TControlFn.getCookie(options.cookie) != null){
						TControlFn.getJsonpData(options.url,{
							state:"DONE"
							,key:TControlFn.getCookie(options.cookie)
							,domain:options.domain
							,callback:"TControl.setCallback"
						});
					}
				}
			});
			
			
			return this;
		},
		setFunc:function(fn){
			state.type = "func";
			state.fn = fn;
			state.use = true;

			this.getJsonpData(options.url,{
				state:"INIT"
				,domain:options.domain
				,callback:"TControl.setCallback"
			});
		},
		setHref:function(url,target){
			//DB 장애시 bypass
			if(state.bypass){
				location.href = url;
			} else {
				state.type = "href";
				state.url = url;
				state.target = target;
				state.use = true;

				this.getJsonpData(options.url,{
					state:"INIT"
					,domain:options.domain
					,callback:"TControl.setCallback"
				});
			}
		},
		setCallback:function(data){
			data = eval("("+data+")");
			ttl  = options.ttl;

			if(jsonpTimeout){
				clearTimeout(jsonpTimeout);
				jsonpTimeout = null;
				jsonpTimeoutCnt = 0;
			}
			
			if( !(data['TTL'] === undefined || data['TTL'] == '') )
			{
				ttl = parseInt(data['TTL'],10);
			}


			if(!state.use && data['STATE'] != "END") return;
			
			if(parseInt(data['WAITCNT'],10) == 0){
				data['STATE'] = "DONE";
			}
			
			switch(data['STATE']){
				case 'INIT':
					state.state = "WAIT";
					state.key = data['KEY'];
					state.maxWaitCnt = data['WAITCNT'];
					state.nowWaitCnt = data['WAITCNT'];
					state.waittimeMin = data['WAITTIME_MIN'];
					state.waittimeSec = data['WAITTIME_SEC'];
					this.setWaitBox(true);
					setTimeout(function(){
						TControl.getJsonpData(options.url,{
							state:state.state
							,key:state.key
							,waitcnt:state.nowWaitCnt
							,domain:options.domain
							,callback:"TControl.setCallback"
						});
					},ttl*1000);
					
					break;
				case 'WAIT':
					state.state = "WAIT";
					state.key = data['KEY'];
					state.nowWaitCnt = data['WAITCNT'];
					state.waittimeMin = data['WAITTIME_MIN'];
					state.waittimeSec = data['WAITTIME_SEC'];

					this.setWaitBox(true);
					setTimeout(function(){
						TControl.getJsonpData(options.url,{
							state:state.state
							,key:state.key
							,waitcnt:state.nowWaitCnt
							,domain:options.domain
							,callback:"TControl.setCallback"
						});
					},ttl*1000);
					break;
				case 'DONE':
					state.key = data['KEY'];
					this.setCookie(options.cookie,state.key);
					switch(state.type){
						case 'href':
							if(!state.target || state.target=="") state.target = "_self";
							window.open(state.url,state.target);
							this.setWaitBox(false);
							break;
						case 'func':
							state.fn();
							break;
					}
					break;
				case 'END':
					this.delCookie(options.cookie);
					break;
				case 'ERROR':	//DB 장애시
					switch(state.type){
						case 'href':
							if(!state.target || state.target=="") state.target = "_self";
							window.open(state.url,state.target);
							this.setWaitBox(false);
							break;
						case 'func':
							state.fn();
							break;
					}
					break;
			}
		},
		getJsonpData:function(url,data){
			if(jsonpTimeout){
				clearTimeout(jsonpTimeout);
				jsonpTimeout = null;
			}
			
			if(jsonpTimeoutCnt <= options.maxInterval){
				jsonpTimeout = setTimeout(function(){
					jsonpTimeoutCnt++;
					TControl.getJsonpData(url,data);
				},options.timeout * 1000);
			}
		
			var queryStringArr = [];
			var queryString = "";
			var script = document.createElement("SCRIPT");
			var temp_script = document.getElementById("_temp_script_");
			for(i in data){
				queryStringArr[queryStringArr.length] = i+"="+data[i];
			}
			queryString = queryStringArr.join("&");
			
			if(temp_script){
				temp_script.parentNode.removeChild(temp_script);
			}
			
			script.type = "text/javascript";
			script.id = "_temp_script_";
			script.src = url+"?"+queryString;
			document.body.appendChild(script);
		},
		setWaitBox:function(display){
			if(display){
				stateElem.bgDiv.style.display = "block";
				stateElem.stateDiv.style.display = "block";
				stateElem.absoluteDiv.style.display = "block";
				
				stateElem.stateText.innerHTML = state.nowWaitCnt+"/"+state.maxWaitCnt;

				//예상 대기시간
				try{
					timeText = '예상 대기시간 : ';
					timeText += state.waittimeMin>0?state.waittimeMin+'분 ':'';
					timeText += state.waittimeSec>=0?state.waittimeSec+'초':'';
					stateElem.waittime.innerHTML = timeText;
				}catch(e){}
				
				stateElem.progressBar.style.width = Math.round( (parseInt(state.maxWaitCnt - state.nowWaitCnt,10)/parseInt(state.maxWaitCnt,10))*100 ) + "%";
				state.use = true;
			} else {
				stateElem.bgDiv.style.display = "none";
				stateElem.stateDiv.style.display = "none";
				stateElem.absoluteDiv.style.display = "none";
				state.use = false;
			}
		},
		domReady:function(fn){
			var domReadySetTimeout = null;
			var domReadyRunCheck = false;
			var domReadyFunction = function(){
				if(domReadyRunCheck) return;
				if(window && document && document.body){
					domReadyRunCheck = true;
					try{
						document.removeEventListener( "DOMContentLoaded", domReadyFunction, false );
						window.removeEventListener( "load", domReadyFunction, false );
					}catch(e){}
					fn();
				} else {
					domReadySetTimeout = setTimeout(domReadyFunction,10);
				}
			};
			
			try{
				document.addEventListener( "DOMContentLoaded", domReadyFunction, false );
				window.addEventListener( "load", domReadyFunction, false );
			}catch(e){
				setTimeout(domReadyFunction,10);
			}
		},
		getDomain:function(){
			var tempDomain = document.location.href;
			var temp = tempDomain.split("//");
			tempDomain = temp[1].substring(0,temp[1].indexOf("/"));
			
			if(tempDomain == "intro.uway.com"){
				temp[1] = temp[1].replace("intro.uway.com/","");
				tempDomain = temp[1].substring(0,temp[1].indexOf("/"));
				tempDomain = "intro.uway.com/"+tempDomain;
			}

			return tempDomain;
		},
		getCookie:function(sKey) {
			if (!sKey) { return null; }
		    return decodeURIComponent(document.cookie.replace(new RegExp("(?:(?:^|.*;)\\s*" + encodeURIComponent(sKey).replace(/[\-\.\+\*]/g, "\\$&") + "\\s*\\=\\s*([^;]*).*$)|^.*$"), "$1")) || null;
		},
		setCookie:function(sKey, sValue, vEnd, sPath, sDomain, bSecure) {
			if(!sKey || /^(?:expires|max\-age|path|domain|secure)$/i.test(sKey)) { return false; }
			if(!vEnd){ vEnd = 0; }
			if(!sPath){ sPath = "/"; }
			if(!sDomain){ sDomain = this.getDomain(); }

			//intro.uway.com 쿠키 처리
			if(/^(intro.uway.com)/.test(sDomain)){
				var temp = sDomain.split("/");
				sDomain = temp[0];	//도메인
				sPath = "/"+temp[1];	//대학별 dir
			}

			var sExpires = "";
			if (vEnd) {
				switch (vEnd.constructor) {
					case Number:
						sExpires = vEnd === Infinity ? "; expires=Fri, 31 Dec 9999 23:59:59 GMT" : "; max-age=" + vEnd;
						break;
					case String:
						sExpires = "; expires=" + vEnd;
						break;
					case Date:
						sExpires = "; expires=" + vEnd.toUTCString();
						break;
				}
			}
			document.cookie = encodeURIComponent(sKey) + "=" + encodeURIComponent(sValue) + sExpires + (sDomain ? "; domain=" + sDomain : "") + (sPath ? "; path=" + sPath : "") + (bSecure ? "; secure" : "");
			return true;
		},
		delCookie:function(sKey, sPath, sDomain) {
			if (!this.getCookie(sKey)) { return false; }
			if(!sPath){ sPath = "/"; }
			if(!sDomain){ sDomain = this.getDomain(); }

			//intro.uway.com 쿠키 처리
			if(/^(intro.uway.com)/.test(sDomain)){
				var temp = sDomain.split("/");
				sDomain = temp[0];	//도메인
				sPath = "/"+temp[1];	//대학별 dir
			}

			document.cookie = encodeURIComponent(sKey) + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT" + (sDomain ? "; domain=" + sDomain : "") + (sPath ? "; path=" + sPath : "");
			return true;
		}
		
	};
	
	TControl = new TControlFn.init();
})();