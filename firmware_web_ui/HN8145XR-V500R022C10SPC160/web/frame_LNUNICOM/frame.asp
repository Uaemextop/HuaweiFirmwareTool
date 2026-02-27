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
var sptUserType = '1';
var sysUserType = '0';
var MenuName = "";
var StartIndex = 1;
var Menu2Path = "";
var authMode = 0;
var Passwordmode = 0;
var changeMethod = 999;
var UpgradeFlag = 0;
var SaveDataFlag = 0;
var menuArray = null;
var RouteFlag = 0;
var RouteContent = "";
var unicomWlanPage = "";
var productName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var curLanguage = '<%HW_WEB_GetCurrentLanguage();%>';
var menuArray = <%HW_WEB_GetWebMenuArray();%>;
var curUserType = '<%HW_WEB_GetUserType();%>';

document.title = productName;
var ajaxInfo = null;
function GetIdByUrl(Type, BaseUrl)
{	
	var NewId = Type+"_";
	var MarkEnd="";
	try{
		var lastindex = BaseUrl.lastIndexOf('/');
		if( lastindex > -1 )
		{
			NewId += BaseUrl.substring(lastindex+1, BaseUrl.length);
		}
		else
		{
			NewId += BaseUrl;
		}
		
		if(NewId.indexOf("?") > -1)
		{
			MarkEnd = NewId.split("?")[1];
		}
		
		NewId = NewId.split(".")[0]+MarkEnd;
		
	}catch(e){
		NewId += Math.round(Math.random() * 10000);
	}
	return NewId;
}

function setCookie(name, value) {
  var expdate = new Date();
  var argv = setCookie.arguments;
  var argc = setCookie.arguments.length;
  var expires = (argc > 2) ? argv[2] : null;

  var path = '/';
  var domain = (argc > 4) ? argv[4] : null;
  var secure = (argc > 5) ? argv[5] : false;
  if(expires!=null) expdate.setTime(expdate.getTime() + ( expires * 1000 ));
  document.cookie = name + '=' + escape (value) +((expires == null) ? '' : ('; expires='+ expdate.toGMTString()))
  +((path == null) ? '' : ('; path=' + path)) +((domain == null) ? '' : ('; domain=' + domain))
  +((secure == true) ? '; secure' : '');
}

function getCookieVal(off) {
  var str = document.cookie.indexOf (';', off);
  if (str == -1) {
    str = document.cookie.length;
  }
  return unescape(document.cookie.substring(off, str));
}

function getCookie(name) {
  var cookieLen = document.cookie.length;
  var args = name + '=';
  var len = args.length;
  var i = 0;
  while (i < cookieLen) {
    var j = i + len;
    if (document.cookie.substring(i, j) == args)
      return getCookieVal(j);
    i = document.cookie.indexOf(' ', i) + 1;
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
        
        this.$content.on("load", function() {
        	frame.$content.show();
            frame.setContentHeight();
        });


        this.menuItems = menuArray;
    },

    initElement : function() {
		var MenuJumpIndexJs = getCookie("MenuJumpIndex");
    	$("#headerTitle").text(productName);
    	
    	this.setLogoutElement(curLanguage);
    	
    	if (this.menuItems.length > 0) {
            this.addMenuItems(this.$mainMenu, this.menuItems, "main");
			if(MenuJumpIndexJs==null)
			{
				this.addMenuItems(this.$subMenu, this.menuItems[0].subMenus, "sub");
				this.addMenuItems(this.$sub3Menu, this.menuItems[0].subMenus[0].subMenus, "sub3");
				this.setContentPath(this.menuItems[0].subMenus[0].url);
			}
			else
			{
				this.addMenuItems(this.$subMenu, this.menuItems[MenuJumpIndexJs].subMenus, "sub");
				this.addMenuItems(this.$sub3Menu, this.menuItems[MenuJumpIndexJs].subMenus[0].subMenus, "sub3");
				this.setContentPath(this.menuItems[MenuJumpIndexJs].subMenus[0].url);
				
			}
			setCookie("MenuJumpIndex", "0");
        }
    },

    addMenuItems : function(element, menus, type) {
    	var frame = this;
		var MenuJumpIndexJs = getCookie("MenuJumpIndex");
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
                    if (!frame.ischangeMenu()) {
                        return;
                    }
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
                if (!frame.ischangeMenu()) {
                    return;
                }
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
        this.$content.attr("src", url);
    },
        
    ischangeMenu: function() {
        var msg;
        console.log(UpgradeFlag);
        if (UpgradeFlag == 1) {
            if(curLanguage == 'chinese') {
            msg = '提醒:系统正在升级，离开本页面会导致升级失败。强烈建议您点击\"取消\"，停留在本页面，直到升级成功。';
        } else if(curLanguage == 'english') {
            msg = 'Note: Upgrade will be interrupted and the device might not boot successfully next time if you switch to another page. It is strongly recommended to press cancel and remain on this page until the upgrade is complete.';
        }
    
        if(confirm(msg)) {
            UpgradeFlag = 0;
            if (ajaxInfo) {
                ajaxInfo.abort()
            }
            return true;
            } else {
                return false;
            }
        } else {
            return true;
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
    	if(curLanguage == "english") {
    		$("#headerLogout span").html("Logout");
    	} else if(curLanguage == "chinese") {
    		$("#headerLogout span").html("退出");
    	}
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
            if (UpgradeFlag == 1) {
                alert("正在升级，请稍后。");
                return;
            }
			frame.clickLogout();
        });
    },

	setCopyRightInfo : function(language) {
        if (language == "chinese") {
            $("#footerText").html("版权所有 © 2023 华为技术有限公司。保留一切权利。");
        } else if (language == "english") {
            $("#footerText").html("Copyright © 2023 Huawei Technologies Co., Ltd. All rights reserved. ");
        }
    },
    clickLogout : function() {
        setCookie("MenuJumpIndex", "0");
        LogoutWithPara("", "/CU.html", true, curUserType);
    },
	show : function() {
        var frame = this;
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
