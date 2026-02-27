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
var Menu3Path = "";
var menu2 = 0;
var authMode = 0;
var Passwordmode = 0;
var changeMethod = 999;
var manageFlag = 0;
var UpgradeFlag = 0;
var SaveDataFlag = 0;
var menuArray = null;
var RouteFlag = 0;
var RouteContent = "";
var SaveLogContent = "";
var curCfgMode = "";

function stManageFlag(ManageFlag) {
	manageFlag = ManageFlag;
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
		this.$content.load(function() {
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
				document.title = productName;
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
		$.ajax({
			type : "POST",
			async : false,
			cache : false,
			url : "../html/ssmp/common/getCfgMode.asp",
			success : function(data) {
				curCfgMode = data;
			}
		});
	},
	initElement : function() {
		$("#productTypeName").text(productName);
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
					element.append('<td class="main_item" id= '+ menus[i].id +'>' + '<div class="item_top_bg"></div>' + '<div class="item_link">' + '<a rel="' + menus[i].url
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
					str += '<span class="sub2itemspan" id= '+ menus[i].id +'><a rel="' + menus[i].url + '" rev="' + i + '">' + menus[i].name + '</a></span>|';
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
					element.append('<p class="sub3item" id= '+ menus[i].id +'><a rev="' + i + '" rel="' + menus[i].url + '">' + menus[i].name + '</a></p>');
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
				msg = '提醒:系统正在升级，离开本页面会导致升级失败。强烈建议您点击\"取消\"，停留在本页面，直到升级成功。';
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
		frame.getRemoteData();
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
	    $('#nav .sub3item a').eq(thirdMenuIdx).trigger("click",[false]);
	}
};

Frame.show();