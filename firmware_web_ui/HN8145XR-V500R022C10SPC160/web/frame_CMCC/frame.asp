var ssidIdx = 0;
var changeWlanClick = 1;
var WlanBasicPage = '2G';
var WlanAdvancePage = '2G';
var WlanSTAPIN = '';
var lanDevIndex = 1;
var QoSCurInterface = '';
var DDNSProvider = '';
var ripIndex = "";
var previousPage = "";
var preAddDomain = "";
var editIndex = -1;
var editDomain = '';
var curLanguage = "chinese"; 
var sptUserType = '1';
var sysUserType = '0';
var MenuName = "";
var StartIndex = 1;
var Menu2Path = "";
var Menu3Path = "";
var menu2 = 0;
var authMode = 0;
var Passwordmode = 0;
var changeMethod = 999;
var manageFlag = 0;
var UpgradeFlag = 0;
var SaveDataFlag = 0;
var RouteFlag = 0;
var RouteContent = "";
var SaveLogContent = "";
var productName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
var menuArray = <%HW_WEB_GetWebMenuArray();%>;
var JscmccTypeFt = '<%HW_WEB_GetFeatureSupport(FT_WEB_PDTTYPE_JSCMCC);%>';
var PotsNum = '<%HW_WEB_GetPortNum();%>';
var TypeJsNoVoiceGE = "CMC-01A";
var TypeJsVoiceGE = "CMC-01B";	
var TypeJsNoVoiceGpon = "CMC-02A";
var TypeJsVoiceGpon = "CMC-02B";		
var TypeJsNoVoiceEpon = "CMC-03A";
var TypeJsVoiceEpon = "CMC-03B";		

document.title = productName;

function stManageFlag(ManageFlag) {
	// this.domain = domain;
	manageFlag = ManageFlag;
}

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

function GetNameById(Type, BaseId)
{	
	var NewId = Type+"_";
	var MarkEnd="";
	try{
		var lastindex = BaseId.lastIndexOf('_');
		if( lastindex > -1 )
		{
			NewId += BaseId.substring(lastindex+1, BaseId.length);
		}
		else
		{
			NewId += BaseId;
		}
	}catch(e){
		NewId += BaseId;
	}
	
	return NewId;
}

var Frame = {
	menuItems : [],
	mainMenuCounter : 0,
	subMenuCounter : 0,
	sub2MenuCounter : 0,
	$mainMenu : null,
	$content : null,
	init : function() {
		this.initData();
		this.initElement();
	},
	initData : function() {
		var frame = this;

		this.mainMenuCounter = 0;
		this.subMenuCounter = 0;

		this.$mainMenu = $("#content_mainitems table tr");
		this.$content = $("#frameContent");

		this.$content.on("load", function() {
			// frame.$content.show();
			frame.setContentHeight();
		});

		this.menuItems = menuArray;
	},

	initElement : function() {
		if (JscmccTypeFt == 1)
		{
			if(PotsNum == 0)
			{
				if (ontPonMode == 'gpon' || ontPonMode == 'GPON')
				{
					$("#productTypeName").text(TypeJsNoVoiceGpon);
				}
				else if(ontPonMode == 'epon' || ontPonMode == 'EPON')
				{
					$("#productTypeName").text(TypeJsNoVoiceEpon);
				}
				else
				{
					$("#productTypeName").text(TypeJsNoVoiceGE);
				}
			}
			else
			{
				if (ontPonMode == 'gpon' || ontPonMode == 'GPON')
				{
					$("#productTypeName").text(TypeJsVoiceGpon);
				}
				else if (ontPonMode == 'epon' || ontPonMode == 'EPON')
				{
					$("#productTypeName").text(TypeJsVoiceEpon);
				}
				else
				{
					$("#productTypeName").text(TypeJsVoiceGE);
				}
			}
		}
		else
		{
            $("#productTypeName").text(productName);
		}
		this.setLogoutElement();
		this.addMenuItems(this.$mainMenu, this.menuItems, "main");
		this.$mainMenu.find('.main_item .item_link a').eq(0).click();
	},
	addMenuItems : function(element, menus, type) {
		var frame = this;
		switch (type) {
			case 'main' :
				this.mainMenuCounter = 0;
				for (var i = 0, len = menus.length; i < len; i++) {
				var maindivname = GetNameById("maindiv", menus[i].id);
				var mainRelname = GetNameById("mainrel", menus[i].id);
				var mainTdname = GetNameById("maintd", menus[i].id);
				element.append('<td name="' + mainTdname + '" class="main_item" id= '+ menus[i].id +'>' + '<div class="item_top_bg"></div>' + '<div name="' + maindivname + '" class="item_link">' + '<a name="' + mainRelname + '" rel="' + menus[i].url
							+ '" rev="' + i + '">' + menus[i].name + '</a>' + '</div>' + '</td>');
				}
				var tdEls = element.children('td');
				tdEls.find('.item_link a').mouseover(function() {
					$(this).css({
						'color' : '#F0422A',
						'text-decoration' : 'underline'
					});
				}).mouseout(function() {
					$(this).css({
						'color' : '#000000',
						'text-decoration' : 'none'
					});
				}).click(function() {
					if (!tdEls.eq(this.rev).is(".hover")) {
						$('#LocationDisplay').text($(this).text());
						
						tdEls.eq(frame.mainMenuCounter).removeClass("hover");
						tdEls.eq(this.rev).addClass("hover");
						
						frame.mainMenuCounter = this.rev;
						frame.addMenuItems($('#content_seconditems table tr td'), menus[this.rev].subMenus, "sub2");
						MenuName = menus[this.rev].name;
						
						$('#content_seconditems table tr td .sub2itemspan a').eq(0).click();
					}
				});
				break;
			case 'sub2' :
				frame.subMenuCounter = 0;
				var str = '|';
				for (var i = 0, len = menus.length; i < len; i++) {
					var subspanname = GetIdByUrl("subspan", menus[i].url);
					var subRelname = GetIdByUrl("subrel", menus[i].url);
					str += '<span name="' + subspanname + '" class="sub2itemspan" id= '+ menus[i].id +'><a name="' + subRelname + '" rel="' + menus[i].url + '" rev="' + i + '">' + menus[i].name + '</a></span>|';
				}
				element.html(str);
				element.find('.sub2itemspan a').mouseover(function() {
					$(this).css({
						'text-decoration' : 'underline'
					});
				}).mouseout(function() {
					$(this).css({
						'text-decoration' : 'none'
					});
				}).click(function() {
					var sub2Els = element.children(".sub2itemspan");
					sub2Els.eq(frame.subMenuCounter).removeClass("hover");
					sub2Els.eq(this.rev).addClass("hover");
					frame.addMenuItems($('#nav'), menus[this.rev].subMenus, "sub3");
					frame.subMenuCounter = this.rev;
					
					$('#nav .sub3item a').eq(0).click();
				});
				break;

			case 'sub3' :
				element.empty();
				frame.sub2MenuCounter = 0;
				for (var i = 0, len = menus.length; i < len; i++) {
					var subPname = GetIdByUrl("subspan", menus[i].url);
					var sub3Relname = GetIdByUrl("subrel", menus[i].url);
					element.append('<p name="' + subPname + '" class="sub3item" id= '+ menus[i].id +'><a name="' + sub3Relname + '" rev="' + i + '" rel="' + menus[i].url + '">' + menus[i].name + '</a></p>');
				}
				element.find('.sub3item a').mouseover(function() {
					$(this).css({
						'text-decoration' : 'underline'
					});
				}).mouseout(function() {
					$(this).css({
						'text-decoration' : 'none'
					});
				}).click(function(event,userPara) {

			             var sub3Els = element.children(".sub3item");
				
				     sub3Els.eq(frame.sub2MenuCounter).removeClass("hover");
				     sub3Els.eq(this.rev).addClass("hover");
					
				     frame.sub2MenuCounter = this.rev;
				     if('undefined' != typeof(userPara)){
				        return;   
				     }
				     frame.setContentPath(this.rel);
					
				});
				break;
		}
	},
	setContentPath : function(url) {
		var msg;
		if (UpgradeFlag == 1) {
			if (curLanguage == 'chinese') {
				msg = '提醒:系统正在升级，离开本页面会导致升级失败。强烈建议您点击\"取消\"，停留在本页面，直到升级成功。';
			} else if (curLanguage == 'english') {
				msg = 'Note: Upgrade will be interrupted and the device might not boot successfully next time if you switch to another page. It is strongly recommended to press cancel and remain on this page until the upgrade is complete.';
			}
			if (confirm(msg)) {
				UpgradeFlag = 0;
				this.$content.attr("src", url);
			}
		} else {
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
				height = Math.max(height, 490);
				$("#center").height(height);
				$("#center div").height(height);
				$("#frameContent").height(height);
			} catch (e) {
			}
		}, 200);
	},
	setLogoutElement : function() {
		var frame = this;
		if ( ('CMCC' == CfgMode.toUpperCase())||('JSCMCC' == CfgMode.toUpperCase()))	
		{
		$("#header_logo #buttonLogout").mouseover(function() {
			$(this).css({
				'color' : '#FFFFFF',
				'text-decoration' : 'underline'
			});
		}).mouseout(function() {
			$(this).css({
				'color' : '#FFFFFF',
				'text-decoration' : 'none'
			});
		}).click(function() {
			frame.clickLogout();
		});
		}
		else{
			$("#header_logo #buttonLogout").mouseover(function() {
			$(this).css({
				'color' : '#F0422A',
				'text-decoration' : 'underline'
			});
		}).mouseout(function() {
			$(this).css({
				'color' : '#0436A5',
				'text-decoration' : 'none'
			});
		}).click(function() {
			frame.clickLogout();
		});
		}
	},
	clickLogout : function() {
		logoutfunc();
	},
	show : function() {
		var frame = this;
		$(document).ready(function() {
			frame.init();
		});
	},
	changeMenuShow:function(mainMenuId,secMenuId,thirdMenuId){
	    var firstMenuIdx = 0;
	    var secMenuIdx = 0;
	    var thirdMenuIdx = 0;

	    this.$mainMenu.find('.main_item').each(function(i,menu){
	        if(mainMenuId == menu.id){
	            firstMenuIdx = i;
	        }
	    });
	    this.$mainMenu.find('.main_item .item_link a').eq(firstMenuIdx).click();
	    $('#content_seconditems table tr td .sub2itemspan').each(function(i,menu){
	        if(secMenuId == menu.id){
	            secMenuIdx = i;
	        }
	    });
	    $('#content_seconditems table tr td .sub2itemspan a').eq(secMenuIdx).click();
	    $('#nav .sub3item').each(function(i,menu){
	        if(thirdMenuId == menu.id){
	            thirdMenuIdx = i;
	        }
	    });
	    $('#nav .sub3item a').eq(thirdMenuIdx).trigger("click");
	}
};

Frame.show();