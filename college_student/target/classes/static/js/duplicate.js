(function ($) {
    $.fn.DuplicateWindow = function () {
        var localStorageTimeout = (5) * 1000;
        var localStorageResetInterval = (1/2) * 1000;
        var localStorageTabKey = 'my-application-browser-tab';
        var sessionStorageGuidKey = 'browser-tab-guid';

        var ItemType = {
            Session: 1,
            Local: 2
        };

        function setCookie(name, value, days) {
            var expires = "";
            if (days) {
                var date = new Date();
                date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
                expires = "; expires=" + date.toUTCString();
            }
            document.cookie = name + "=" + (value || "") + expires + "; path=/";
        }
        function getCookie(name) {
           var nameEQ = name + "=";
            var ca = document.cookie.split(';');
            for (var i = 0; i < ca.length; i++) {
                var c = ca[i];
                while (c.charAt(0) == ' ') c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
            }
            return null;
        }

        function GetItem(itemtype) {
            var val = "";
            switch (itemtype) {
                case ItemType.Session:
                    val = window.name;
                    break;
                case ItemType.Local:
                    val = decodeURIComponent(getCookie(localStorageTabKey));
                    if (val == undefined)
                        val = "";
                    break;
            }
            return val;
        }

        function SetItem(itemtype, val) {
            switch (itemtype) {
                case ItemType.Session:
                    window.name = val;
                    break;
                case ItemType.Local:
                    setCookie(localStorageTabKey, val);
                    break;
            }
        }

        function createGUID() {
            this.s4 = function () {
                return Math.floor((1 + Math.random()) * 0x10000)
                  .toString(16)
                  .substring(1);
            };
            return this.s4() + this.s4() + '-' + this.s4() + '-' + this.s4() + '-' + this.s4() + '-' + this.s4() + this.s4() + this.s4();
        }

        function TestIfDuplicate() {
            var sessionGuid = GetItem(ItemType.Session) || createGUID(); 
        	SetItem(ItemType.Session, sessionGuid);
            var val = GetItem(ItemType.Local);
            var tabObj = (val == "" ? null : JSON.parse(val)) || null;
            if (tabObj === null || (tabObj.timestamp < (new Date().getTime() - localStorageTimeout)) || tabObj.guid === sessionGuid) {
              function setTabObj() {
                    var newTabObj = {
                        guid: sessionGuid,
                        timestamp: new Date().getTime()
                    };
                    SetItem(ItemType.Local, JSON.stringify(newTabObj));
                }
                setTabObj();
                setInterval(setTabObj, localStorageResetInterval);
                return false;
            } else {
                return true;
            }            
        }

        window.IsDuplicate = function () {
            return (TestIfDuplicate() == true ? "warning" : "login");
        };
        
        window.getFunc = function(){        	
        	if(typeof getCookie == 'undefined'){
        		return null;
        	}
        	var cook = JSON.parse(getCookie(localStorageTabKey));
        	var config = {
        			'timeout' :localStorageTimeout,
        			'interval':localStorageResetInterval
        	}
        	cook['timeout'] = localStorageTimeout;
        	cook['interval'] = localStorageResetInterval;
        	
        	return JSON.stringify(cook);
        }
        
        $(window).on("beforeunload", function () {
        	if (TestIfDuplicate() == false) {
                SetItem(ItemType.Local, "");
            }
        })
    }
    $(window).DuplicateWindow();
}(jQuery));
