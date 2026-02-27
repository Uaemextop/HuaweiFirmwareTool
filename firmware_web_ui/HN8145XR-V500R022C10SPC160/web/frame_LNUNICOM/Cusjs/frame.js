var ssidIdx = 0;
var changeWlanClick = 1;
var WlanBasicPage = '2G';
var WlanAdvancePage = '2G';
var lanDevIndex = 1;
var QoSCurInterface = '';
var DDNSProvider = '';
var ripIndex = "";
var previousPage = "";
var preAddDomain = "";
var editIndex = -1;
var editDomain = '';
var curWebFrame = null;
var curWebMenuPath = null;
var productName = null; 
var curLanguage = "chinese";
var sptUserType = '1';
var sysUserType = '0';
var curUserType = null;
var MenuName = "";
var StartIndex = 1;
var Menu2Path = "";
var pageName11 = null;
var authMode = 0;
var Passwordmode = 0;
var changeMethod = 999;
var UpgradeFlag = 0;
var SaveDataFlag = 0;
var menuArray = null;
var RouteFlag = 0;
var RouteContent = "";
var unicomWlanPage = "";

function SetCookie(name, value)
{
    var expires = (SetCookie.arguments.length > 2) ? SetCookie.arguments[2] : null;
    var domain = (SetCookie.arguments.length > 4) ? SetCookie.arguments[4] : null;
    var secure = (SetCookie.arguments.length > 5) ? SetCookie.arguments[5] : false;

    var cookiepath = "/";
    if (expires != null) {
        var expdate = new Date();
        expdate.setTime(expdate.getTime() + (expires * 1000));
    }
    document.cookie = name + "=" + escape (value) + ((expires == null) ? "" : ("; expires=" + expdate.toGMTString())) +
        ((cookiepath == null) ? "" : ("; cookiepath=" + cookiepath)) +((domain == null) ? "" : ("; domain=" + domain)) +
        ((secure == true) ? "; secure" : "");
}

function GetCookieVal(offset)
{
    var cookievalstr = document.cookie.indexOf (";", offset);
    if (cookievalstr == -1)
    cookievalstr = document.cookie.length;
    return unescape(document.cookie.substring(offset, cookievalstr));
}

function GetCookie(name)
{
    var cookieName = name + "=";
    var cookieNameLen = cookieName.length;
    var cookieLen = document.cookie.length;
    var i = 0;
    while (i < cookieLen) {
        var j = i + cookieNameLen;
        if (document.cookie.substring(i, j) == cookieName) {
            return GetCookieVal(j);
        }
        i = document.cookie.indexOf(" ", i) + 1;
        if (i == 0) break;
    }
    return null;
}

var Frame = {
    menuItems : [],
    mainMenuCounter : 0,
    subMenuCounter : 0,
    sub3MenuCounter : 0,
    $mainMenu : null,
    $subMenu : null,
    $sub3Menu : null,
    $content : null,
    init : function() {
        this.initData();
        this.initElement();
    },
    initData : function() {
    	var frame = this;
    	
        this.mainMenuCounter = 0;
        this.subMenuCounter = 0;
        this.sub3MenuCounter = 0;

        this.$mainMenu = $("#headerTab ul");
        this.$subMenu = $("#nav ul");
        this.$sub3Menu = $("#topNav ul");
        this.$content = $("#frameContent");
        this.$content.load(function() {
        	frame.$content.show();
            frame.setContentHeight();
        });

        this.menuItems = menuArray;
    },

    getRemoteData : function() {
	  $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "asp/getMenuArray.asp",
            success : function(data) {
                 menuArray  = dealDataWithFun(data);
            }
        });
			 
        $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "asp/getProductName.asp",
            success : function(data) {
                productName = data;
            }
        });

        $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "../html/ssmp/common/getCurWebFrame.asp",
            success : function(data) {
                curWebFrame = data;
            }
        });
        $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "../html/ssmp/common/getCurWebMenuPath.asp",
            success : function(data) {
                curWebMenuPath = data;
            }
        });
        $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "../html/ssmp/common/getCurUserType.asp",
            success : function(data) {
               	curUserType = data;
            }
        });
        $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "../html/ssmp/common/getPageName.asp",
            success : function(data) {
                pageName11 = data;
            }
        });
    },

    initElement : function() {
		var MenuJumpIndexJs = GetCookie("MenuJumpIndex");
    	$("#headerTitle").text(productName);
    	
    	this.setLogoutElement(curLanguage);
    	
    	if (this.menuItems.length > 0) {
            this.addMenuItems(this.$mainMenu, this.menuItems, "main");
			if(MenuJumpIndexJs==null)
			{
				this.addMenuItems(this.$subMenu, this.menuItems[0].subMenus, "sub");
			}
			else
			{
				this.addMenuItems(this.$subMenu, this.menuItems[MenuJumpIndexJs].subMenus, "sub");
				
			}
			this.addMenuItems(this.$sub3Menu, this.menuItems[MenuJumpIndexJs].subMenus[0].subMenus, "sub3");
			this.setContentPath(this.menuItems[MenuJumpIndexJs].subMenus[0].url);
			SetCookie("MenuJumpIndex", "0");
        }
    },

    addMenuItems : function(element, menus, type) {
    	var frame = this;
		var MenuJumpIndexJs = GetCookie("MenuJumpIndex");
    	element.empty();
		if(type == "main") 
		{
			this.mainMenuCounter = 0;
			
			for (var i = 0, len = menus.length; i < len; i++) {
				element.append('<li value="' + i + '"name="' + menus[i].name + '"id="mainMenu_' + i + '">' +
					'<div class="tabBtnCenter">' + menus[i].name + '</div>' +
				'</li>');
		    }
			
			if(MenuJumpIndexJs==null)
			{
				element.children("li").eq(0).addClass("hover");
			}
			else
			{
				element.children("li").eq(MenuJumpIndexJs).addClass("hover");
			}
            element.children("li").click(function(event,userPara) {
                if (!element.children("li").eq(this.value).is(".hover")) {
					if(MenuJumpIndexJs != frame.mainMenuCounter)
					{	
						element.children("li").eq(MenuJumpIndexJs).removeClass("hover");
					}
					
                    element.children("li").eq(frame.mainMenuCounter).removeClass("hover");
                    element.children("li").eq(this.value).addClass("hover");
                    frame.mainMenuCounter = this.value;
                    frame.addMenuItems($("#nav ul"), menus[this.value].subMenus, "sub");
                    frame.addMenuItems($("#topNav ul"), (menus[this.value].subMenus)[0].subMenus, "sub3");

                    if('undefined' != typeof(userPara)){
                        return;   
                    }
                    frame.setContentPath(menus[this.value].url);
                }
            });
		}
		else if (type == "sub") 
		{
            this.subMenuCounter = 0;
            for (var i = 0, len = menus.length; i < len; i++) {
                element.append('<li value="' + i + '"name="' + menus[i].name + '"id="secMenu_' + i + '"><div>' + menus[i].name + '</div></li>');
            }
            element.children("li").eq(0).addClass("hover");
            element.children("li").click(function(event,userPara) {
                element.children("li").eq(frame.subMenuCounter).removeClass("hover");
                element.children("li").eq(this.value).addClass("hover");
                frame.subMenuCounter = this.value;
                frame.addMenuItems($("#topNav ul"), menus[this.value].subMenus, "sub3");

                if('undefined' != typeof(userPara)){
                    return;   
                }
                frame.setContentPath(menus[this.value].url);
        	});
        }
		else if (type == "sub3") 
		{
            this.sub3MenuCounter = 0;
			if(menus==null)
			{
				return;
			}
			
            for (var i = 0, len = menus.length; i < len; i++) {
                element.append('<li value="' + i + '"name="' + menus[i].name + '"id="thirdMenu_' + i + '">' + '<div class="tabBtnLeft"></div>' + '<div class="tabBtnCenter">' + menus[i].name + '</div>' + '<div class="tabBtnRight"></div>'+'</li>');
            }
            element.children("li").eq(0).addClass("hover");
            element.children("li").click(function(event,userPara) {
                element.children("li").eq(frame.sub3MenuCounter).removeClass("hover");
                element.children("li").eq(this.value).addClass("hover");
                frame.sub3MenuCounter = this.value;
                
                if('undefined' != typeof(userPara)){
                    return;   
                }
                frame.setContentPath(menus[this.value].url);
            });
        }
    },

    setContentPath : function(url) {
    	
		var msg;
		if (UpgradeFlag == 1)
		{
			msg = '提醒:系统正在升级，离开本页面会导致升级失败。强烈建议您点击\"取消\"，停留在本页面，直到升级成功。';
			if(confirm(msg)) 
			{
				UpgradeFlag = 0;
				this.$content.attr("src", url);
			}
		}
		else 
		{
			this.$content.attr("src", url);
		}
    },
    setContentHeight : function() {
        setInterval(function() {
            try {
                var height = 0;
                if (window.ActiveXObject) {
                    height = document.getElementById("frameContent").contentWindow.document.body.scrollHeight;
                }
                else if (window.XMLHttpRequest) {
                    height = document.getElementById("frameContent").contentWindow.document.body.offsetHeight;
                }
			    
                height = Math.max(height, 443);
            } catch (e) {

            }
        }, 200);
    },

    setMenuPath : function() {
    },

    setLogoutElement : function(curLanguage) {
    	$("#headerLogout span").html("退出");
    	var frame = this;
    	
        $("#headerLogout span").mouseover(function() {
            $("#headerLogout span").css({
                "color" : "#9C4500",
                "text-decoration" : "underline"
            });
        });
        $("#headerLogout span").mouseout(function() {
            $("#headerLogout span").css({
                "color" : "#FFFFFF",
                "text-decoration" : "none"
            });
        });
        $("#headerLogout span").click(function() {
			frame.clickLogout();
        });
    },

	setCopyRightInfo : function(language) {
        $("#footerText").html("版权所有 © ##.COPY_RIGHT_YEAR.## 华为技术有限公司。保留一切权利。");

    },
    clickLogout : function() {
        logoutfunc();
    },
	show : function() {
        var frame = this;
        frame.getRemoteData();
        $(document).ready(function() {
            frame.init();
        });
    },
	changeMenuShow:function(mainMenuName,secMenuName,thirdMenuName,reQuestUrl){
	    var firstMenuIdx = 0;
	    var secMenuIdx = 0;
	    var thirdMenuIdx = 0;
	    
	    this.$mainMenu.find('li[id^=\'mainMenu_\']').each(function(i,menu){
	        if(mainMenuName == $(menu).attr("name")){
	            firstMenuIdx = i;
	        }
	    });
	    if(false == reQuestUrl){
	        this.$mainMenu.find('li[id^=\'mainMenu_\']').eq(firstMenuIdx).trigger("click",[false]);
	    }else{
	        this.$mainMenu.find('li[id^=\'mainMenu_\']').eq(firstMenuIdx).click();
	    }
	    
	    this.$subMenu.find('li[id^=\'secMenu_\']').each(function(i,menu){
	        if(secMenuName == $(menu).attr("name")){
	            secMenuIdx = i;
	        }
	    });
	    if(false == reQuestUrl){
	        this.$subMenu.find('li[id^=\'secMenu_\']').eq(secMenuIdx).trigger("click",[false]);
	    }else{
	        this.$subMenu.find('li[id^=\'secMenu_\']').eq(secMenuIdx).click();
	    }

	    this.$sub3Menu.find('li[id^=\'thirdMenu_\']').each(function(i,menu){
	        if(thirdMenuName == $(menu).attr("name")){
	            thirdMenuIdx = i;
	        }
	    });
	    if(false == reQuestUrl){
	        this.$sub3Menu.find('li[id^=\'thirdMenu_\']').eq(thirdMenuIdx).trigger("click",[false]);
	    }else{
	        this.$sub3Menu.find('li[id^=\'thirdMenu_\']').eq(thirdMenuIdx).click();
	    }
	}
};

Frame.show();