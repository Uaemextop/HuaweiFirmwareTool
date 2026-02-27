<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1"><!-IE7 mode->
<meta http-equiv="Pragma" content="no-cache" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(frame.css);%>" rel="stylesheet" type="text/css" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(index.css);%>" rel="stylesheet" type="text/css" />
<script src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script src="/resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>" type="text/javascript" ></script>
<script src="/frameaspdes/<%HW_WEB_Resource(ssmpdes.js);%>" language="JavaScript"></script>
<script src="/Cusjs/<%HW_WEB_CleanCache_Resource(frame.asp);%>" type="text/javascript"></script>

<script language="javascript" type="text/javascript">

</script>

<script language="JavaScript" type="text/javascript">
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var ProductType = '<%HW_WEB_GetProductType();%>';
var IsSupportWifi = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_WLAN);%>';
var UserName = '<%HW_WEB_GetCurUserName();%>';
var ConfigFlag = '<%HW_WEB_GetGuideFlag();%>';
var curUserType = '<%HW_WEB_GetUserType();%>';
var sysUserType = '0';
var IsModifiedPwd = '<%HW_WEB_GetWebUserMdFlag();%>';
var flagTips = true;
var timeout = null;
var curLanguage = '<%HW_WEB_GetCurrentLanguage();%>';
var mngttype = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var logo_singtel = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_SINGTEL);%>';
var telmexwififeature = '<%HW_WEB_GetFeatureSupport(FT_PRODUCT_TELMEX);%>';
var mngtpccwtype = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_PCCW);%>';
var MenuModeVDF = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_PTVDF);%>';
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var IsSmartDev = "<%HW_WEB_GetFeatureSupport(HW_OSGI_FT_BUNDLEINFOWEB);%>";
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var TypeWord_com = '<%HW_WEB_GetTypeWord();%>';
var smartlanfeature = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
document.title = ProductName;
var apcmodefeature = '<%HW_WEB_GetFeatureSupport(FT_SSMP_AP_OPERATION_SWITCH);%>';
var GhnDevFlag = '<%HW_WEB_GetFeatureSupport(FT_SSMP_GHNAP_MNGT);%>';
var curChangeMode = '<%HW_WEB_GetAPChangeModeValue();%>'; 
var apghnfeature = '<%HW_WEB_GetFeatureSupport(FT_SSMP_GHNAP_MNGT);%>';
var videomodefeature = '<%HW_WEB_GetFeatureSupport(HW_AMP_FT_VIDEO_MODE);%>';
var fVideoCoverEnable = '<%HW_WEB_GetVedioCoverEnable();%>';
var DirectGuideFlag = '<%HW_WEB_GetFeatureSupport(FT_CHANGE_GUIDE_LEVEL);%>';
var UnSupportGuide = '<%HW_WEB_GetFeatureSupport(FT_UDO_XGPON_AGUIDE);%>';
var menuJsonData;
var UpgradeFlag = 0;  //0--normal, 1--updating, 2--diagnosing
var E8CAPFlag = '<%HW_WEB_GetFeatureSupport(BBSP_FT_E8CAP_SWITCH);%>';
var VideoFlag = '<%HW_WEB_GetVideoChangeFlag();%>';
var CurrentUpMode = '<%HW_WEB_GetUpMode();%>';
var IsSupportpon2lan = '<%HW_WEB_GetFeatureSupport(FT_PON_UPPORT_CONFIG);%>'; 
var autoadapt = '<%HW_WEB_GetFeatureSupport(FT_SSMP_AUTO_ADAPT);%>';
var adaptResult = '<%HW_WEB_GetCModeAdaptValue();%>';
var appUrl = '<%HW_WEB_GetSPEC(SPEC_STC_APP_URL.STRING);%>';

var aprepeater = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_BbspConfig.UpLinkStatus);%>';
var aprepEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_FeatureList.BBSPCustomization.AutoSelectSlaveApUpPort);%>';
var IsSmartBord = '<%HW_WEB_GetFeatureSupport(FT_SMART_BOARD);%>';
var COMMONV5CMODE = '<%HW_WEB_GetFeatureSupport(BBSP_FT_WAN_COMMONV5);%>';
var isHG8010Hv6 = '<%HW_WEB_GetFeatureSupport(FT_WEB_HG8010HV6_CUT);%>';
var AdaptExist = '<%HW_WEB_IsSupportAd();%>';

var userdevinfonum = "";

function WebUserInfo(domain, ModifyPasswordFlag)
{
	this.domain = domain;
	this.ModifyPasswordFlag = ModifyPasswordFlag;
}
var userInfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.{i}, ModifyPasswordFlag, WebUserInfo);%>;
var c805sctrl = '<%HW_WEB_GetFeatureSupport(FT_C805S_SPECIAL_CONTROL);%>';
var userIdx = (curUserType == sysUserType) ? 1 : 0;
if (userInfo.length == 2) {
	userIdx = 0;
}
var forceModiWebPwdFirstLogin = (c805sctrl == 1) && (userInfo[userIdx].ModifyPasswordFlag == 0);

if(1 != curChangeMode && 1 == aprepEnable)
{
    if(3 == aprepeater)
    {
        curChangeMode = 2;
    }
    else if(8 == aprepeater)
    {
        curChangeMode = 3;
    }
}
if(autoadapt == 1)
{
	curChangeMode = 4;
}
$.ajax({
    type : "POST",
    async : false,
    cache : false,
    url : "asp/getMenuArray.asp",
    success : function(data) {
         menuJsonData  = dealDataWithFun(data);
    }
});


function showCmodePage() 
{   
    document.getElementById("zhezhao").style.display ="block";
    document.getElementById("showcmode").style.display ="none";
    document.getElementById("showcmode1").style.display ="block";   
}
function hideCmodePage() 
{
    document.getElementById("zhezhao").style.display ='none';
    document.getElementById("showcmode").style.display ='none';
    document.getElementById("showcmode1").style.display ='none';
    document.getElementById("1").disabled=false;
    document.getElementById("2").disabled=false;
    document.getElementById("3").disabled=false;
    document.getElementById("4").disabled=false;
    document.getElementById("MdyPwdApply").style.backgroundColor = "#bbbbbb";
    document.getElementById("MdyPwdApply").style.borderColor = "#bbbbbb";
	document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
    document.getElementById("MdyPwdApply1").style.borderColor = "#bbbbbb";
	document.getElementById("MdyPwdApply1").disabled=true;
    if(curChangeMode=='1')
    {
        document.getElementById("5").checked=true;                  
    }
    if(curChangeMode=='2' || curChangeMode=='3')
    {
        document.getElementById("4").checked=true;
    }
	if(curChangeMode=='4')
    {
        document.getElementById("6").checked=true;
    }
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

function DisplayDownAPP()
{
    if (IsSmartBord == "1")
    {
        $("#guidespacethree").css('display', 'block');
        $("#AppDiv").css('display', 'block');
    }
    else
    {
        $("#guidespacethree").css('display', 'none');
        $("#AppDiv").css('display', 'none');
    }
}

function IsModifedFun(){

	if(IsModifiedPwd == 0 && curUserType != sysUserType)
	{
		$("#modifyPwdBox").fadeIn(300);	
	} 
}

function loadframe()
{
    if (parseInt(IsSupportWifi, 10) > 0)
    {
        if (parseInt(mngtpccwtype, 10) == 1 || (parseInt(mngttype, 10) == 1 && curUserType != sysUserType) || COMMONV5CMODE == 0)
        {
            $("#AppDiv").css("display", "none");
            $("#guidespacetwo").css("display", "none");
        }
        else
        {   
            if(1 != IsSmartDev)
            {
                $("#AppDiv").css("display", "none");
                $("#guidespacetwo").css("display", "none");
            }
            else
            {
                $("#AppDiv").css("display", "block");
                $("#guidespacetwo").css("display", "block");
            }
        }
    }
    else if (1 == IsSmartDev)
    {
        $("#AppDiv").css("display", "block");
        $("#guidespacetwo").css("display", "block");
    }   
    
    
    if(parseInt(mngttype, 10) != 1)
    {
        if(parseInt(logo_singtel, 10) != 1)
        {
            if ('TELECENTRO' == CfgMode.toUpperCase())
			{
				$("#headerbrandlog_tel").css("display", "block"); 
			}
			else if ('PLDT2' == CfgMode.toUpperCase() || 'PLDT' == CfgMode.toUpperCase())
			{
				$("#headerbrandlog_pldt").css("display", "block"); 
			}
			else
			{
				$("#headerbrandlog").css("display", "block"); 
			}	  
        }
        else
        {   
            if(TypeWord_com == "COMMON")
            {
                 $("#headerbrandlogSingtel").css("background-image", "url()");
            } 
            $("#headerbrandlogSingtel").css("display", "block");
        }       
    }

	if('DTURKCELL2WIFI' == CfgMode.toUpperCase()){
		if(flagTips)
		{
			IsModifedFun();
			flagTips = false;
		}
		
	}
	
	if (telmexwififeature == 1)
	{
		$("#headerbg").css("background-image", "url()");
		$("#headerbrandlog").css("width", "187px");
		$("#HeaderRightMenu").css("color","#56b2f8");
		$("#headerProductName").css("width", "324px");
		$("#username").css("color","#56b2f8");
		$("#configguidetext").css("color","#56b2f8");
		$("#headerLogoutText").css("color","#56b2f8");
	}

	if((1 == videomodefeature) || (1 == VideoFlag))
	{
    	$("#VideoMode").css("display", "block");
        $("#guidevideospace").css("display", "block");
		setCheck('ckVideoSwitch', fVideoCoverEnable);
	}
	else
	{
		$("#VideoMode").css("display", "none");
        $("#guidevideospace").css("display", "none");
	}
    if(apghnfeature == 1)
    {
        document.getElementById("MdyPwdApply").disabled=true;
        document.getElementById("MdyPwdApply").style.backgroundColor = "#bbbbbb";
        document.getElementById("MdyPwdApply").style.borderColor = "#bbbbbb";       
        $("#AppDiv").css("display", "none");
        $("#cmodeLogout").css("display", "none");
        $("#bssinfo").css("display", "none");
        $("#guidespacetwo").css("display", "none");
        document.getElementById("1").disabled=true;
        document.getElementById("3").disabled=true;
        $("#configguide").css("display", "none");
        $("#guidespaceone").css("display", "none");
        return;
    }
    
    if("" != curChangeMode && 0 != curChangeMode)
    {
        document.getElementById("MdyPwdApply").disabled=true;
        document.getElementById("MdyPwdApply").style.backgroundColor = "#bbbbbb";
        document.getElementById("MdyPwdApply").style.borderColor = "#bbbbbb";
        document.getElementById("MdyPwdApply1").disabled=true;
        document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
        document.getElementById("MdyPwdApply1").style.borderColor = "#bbbbbb";
        $("#AppDiv").css("display", "none");
        $("#bssinfo").css("display", "none");
        
        if(apcmodefeature == 1)
        {       
            document.getElementById("cmodecontent").style.display="none";
            document.getElementById("aprepcontent").style.display="block";
            $("#cmodeLogout").css("display", "block");
            $("#guidespacetwo").css("display", "block");
            
            if(curChangeMode=='1')
            {
                DisplayDownAPP();
                document.getElementById("5").disabled=false;
                document.getElementById("5").checked=true;
                document.getElementById("rtpic5").src="../images/router2.png";
                document.getElementById("rtcontent").style.color="#57b6f0";
                document.getElementById("gcmexplainbridge").style.display="block";
            }
        
            if(curChangeMode=='2' || curChangeMode=='3')
            {
                if(curChangeMode=='2')
                {
                    document.getElementById("gcmexplainap").style.display="block";
                    document.getElementById("wifipic4").src="../images/apmode2.png";
                }
                if(curChangeMode=='3')
                {
                    document.getElementById("cmexplainrep").style.display="block";
                    document.getElementById("wifipic4").src="../images/Ranger2.png";
                }
                document.getElementById("4").disabled=false;
                document.getElementById("4").checked=true;
                document.getElementById("wificontent").style.color="#57b6f0";
            }
			
			if(curChangeMode=='4')
			{
				document.getElementById("autoconsultguide").style.display="block";
				//document.getElementById("hengline1").style.display="block";
				//$("#showcmode1").css("height", "480px");
				document.getElementById("6").disabled=false;
				document.getElementById("6").checked=true;
				document.getElementById("autoadaptpic5").src="../../../images/apmode2.png";
				document.getElementById("autoconsultcontent").style.color="#57b6f0";
				document.getElementById("autoconsultexplain").style.display="block";
				document.getElementById("gcmexplainbridge").style.display="block";

			}
        }
        else
        {
            $("#cmodeLogout").css("display", "none");
            $("#guidespacetwo").css("display", "none");
            if(curChangeMode=='2' || curChangeMode=='3'){
                if(curUserType == sysUserType)
                {
                    if(0 == DirectGuideFlag)
                    {
                        $("#configguide").css("display", "none");
                        $("#guidespaceone").css("display", "none");
                    }
                }
            }
        }
    }
	
	if("VDFPTAP"==CfgMode || CfgMode.toUpperCase() == "TRUEAP")
	{
		$("#cmodeLogout").css("display", "none");
		$("#guidespacetwo").css("display", "none");
	}
	if(0 == AdaptExist)
	{
		document.getElementById('autoconsultguide').style.display = "none";
		document.getElementById('hengline1').style.display = "none";
		$("#showcmode1").css("height", "380px");
	}
    
    if ((isHG8010Hv6 == "1") && (curUserType == sptUserType)) {
        document.getElementById("configguide").style.display = "block";
        document.getElementById("configguide").style.paddingRight = "20px";
    }

}

if ((isHG8010Hv6 == "1") && (curUserType == sptUserType) && (!parseInt(ConfigFlag.split("#")[1], 10))){
    goToGuidePage();
}

if (forceModiWebPwdFirstLogin) {
    goToGuidePage();
}

function goToGuidePage()
{
    if (!ifCanChangeMenu())
    {
        return ;
    }
    
    if(1 == DirectGuideFlag)
    {
        window.location="/CustomApp/userguideframe.asp";
        return;
    }

    if (curUserType == sysUserType && ((1 == smartlanfeature) || (3 == CurrentUpMode && 1 == IsSupportpon2lan)))
    {
        window.location="/CustomApp/adminguideframe.asp";
    }
    else if (curUserType == sysUserType)
    {
        if(1 == apcmodefeature)
        {
            window.location="/CustomApp/adminguideframe.asp";
        }
        else
        {
            if (ProductType == '2')
            {
                window.location = "/CustomApp/adminguideframe.asp";
            }
            else
            {
                window.location="/html/ssmp/cfgguide/guideindex.asp";
            }
        }
    }
    else
    {
        window.location="/CustomApp/userguideframe.asp";
    }
}

function closePwdTips(){
	$("#modifyPwdBox").fadeOut(500);
}

function jumpModifyPwd(){
	var accountUrl = "/html/ssmp/accoutcfg/account.asp"
	closePwdTips();
	onMenuChange1("userconfig",accountUrl);
	
}

function ifCanChangeMenu()
{
    if (UpgradeFlag == 1)
    {
        if(confirm(framedesinfo["mainpage016"]))
        {
            UpgradeFlag = 0;
            return true;
        }
        else
        {
            return false;
        }
    }
    else if (UpgradeFlag == 2)
    {
        if(confirm(framedesinfo["mainpage017"]))
        {
            UpgradeFlag = 0;
            return true;
        }
        else
        {
            return false;
        }
    }

    return true;
}

function toggleQRCodeDisplay(flag)
{
    var Type = flag;
    if (flag == 'auto')
    {
        var displayflag = document.getElementById("D2CodeDivInfo").style.display;
        Type = "block" == displayflag ? "none" : "block";
    }
    $('#D2CodeDivInfo').css("display", Type);
}

function adjustParentHeight()
{
    var menuBar = $("#SecondMenuInfo");
    adjustFrameHeight("maincenter", "menuIframe", 280, (menuBar != null ? menuBar.innerHeight() + 100 : null));
}
</script>
</head>
<body onload="loadframe();">
<div id="modifyPwdBox" style="display:none;">
	<div id="passwordTips" class="passwordTips">
		<div id="pwdCloseBtn" class="pwdCloseBtn">
			<a onclick="closePwdTips();"></a>
		</div>
		<div id="pwdContainer" class="pwdContainer">
			<h2>Notice</h2>
			<p>You are currently using the default login password. Please change this password to improve the network security.</p>
		</div>
		<div id="pwdBtn" class="pwdBtn">
			<a onclick="jumpModifyPwd();">Modify Login Password</a>
			<a style="margin-left: 40px;" onclick="closePwdTips();">Missing transition:UserLogin.Skip</a>
		</div>
	</div>
</div>
<div id="indexpage">
<script>
if (telmexwififeature == 1 )
{
	document.write('<div id="headertelmexbg">');
}
else
{
	document.write('<div id="headerbg">');
}
</script>  
        <div id="header">

        <script>
            if (logo_singtel == true)
            {
                document.write('<div id="headerbrandlogSingtel"></div>');               
            }
			else if ('TELECENTRO' == CfgMode.toUpperCase())
			{
				document.write('<div id="headerbrandlog_tel"></div>');
				document.write('<div id="headerProductName">' + ProductName + '</div>');
			}
			else if ('PLDT2' == CfgMode.toUpperCase() || 'PLDT' == CfgMode.toUpperCase())
			{
				document.write('<div id="headerbrandlog_pldt"></div>');
				document.write('<div id="headerProductName">' + ProductName + '</div>');
			}
            else
            {
                document.write('<div id="headerbrandlog"></div>');
                document.write('<div id="headerProductName">' + ProductName + '</div>');
            }
        </script>
            <div id="HeaderRightMenu">
                <div id="headerLogout">
                    <span id="headerLogoutText" class="HeaderSpanTextGuide" onclick="logoutfunc();"  BindText="mainpage009"></span>

                </div>
                <div id="headeruser">
                    <span id="username" class="HeaderSpanTextGuide" ></span>
                </div>

				<div id="guidespaceone" class="guidespace">
					<div class="guidespacebar"></div>
				</div>
				<div id="configguide">
					<span id="configguidetext" class="HeaderSpanTextGuide" onclick="goToGuidePage();" BindText="mainpage008"></span>
				</div>

                <div id="guidespacetwo" class="guidespace">
                    <div class="guidespacebar"></div>               
                </div>
                <div id="cmodeLogout" >
                    <span id="modechangeText" class="HeaderSpanTextGuide" onclick="showCmodePage();"  BindText="mainpage019"></span>
                </div>
				<div id="guidevideospace" style="display:none;" class="guidespace"><div class="guidespacebar"></div></div>
				<script language="JavaScript" type="text/javascript">
				function setVideoSwitch()
				{
					var isVideo = getCheckVal('ckVideoSwitch');
	
    				if(ConfirmEx("设置模式切换，需重启，是否执行？"))
					{
                         $.ajax({
                            type : "POST",
                            async : true,
                            cache : false,
                            data : "w.VideoCoverEnable=" + isVideo + "&x.X_HW_Token=" + getValue('onttoken'),
                            url : 'set.cgi?w=InternetGatewayDevice.X_HW_VideoCoverService',
            				success : function(data) {

                                 }
                         });
                     }
                     else
                     {
					 	var lastvideo = (isVideo == 0)? 1:0;
                        setCheck('ckVideoSwitch', lastvideo);
                     }
                 }

				</script>

			<div id="VideoMode" title="视频通模式，可解决家庭无网线开IPTV业务场景，可设置为普通模式" style="display:none;float:left;margin-top:16px;margin-right:5px;"><input type="checkbox" name="ckVideoSwitch" id="ckVideoSwitch" style="line-height:30px;vertical-align:middle;" onClick='setVideoSwitch();' ><span class="HeaderSpanTextGuide" >视频通</span></input></div>
			<div><input type="hidden" name="onttoken" id="onttoken" value="<%HW_WEB_GetToken();%>"></div>
                <div id="cmodeLogout" >
                    <span id="modechangeText" class="HeaderSpanTextGuide" onclick="showCmodePage();"  BindText="mainpage019"></span>
                </div>
                <div id="guidespacethree" class="guidespace" style="display: none">
                    <div class="guidespacebar"></div>               
                </div>
                <div id="AppDiv" >
                    <div id="MaPoniterText" >
                        <span class="HeaderSpanTextGuide" BindText="mainpage013"></span>
                    </div>
                    <div id="MaPoniterIcon" ></div>
                    <div id="D2CodeDivInfo">
                        <div id="FirstLineIcon">
                            <div id="phoneicon"><img src="images/D2CodePhone.jpg"></div>
                            <div id="phonetext"><span BindText="mainpage007"></span></div>
                        </div>
                        <div id="D2CodeTop">
                            <div class="D2CodeCornerLeft"></div>
                            <div class="D2CodeCornerRigth"></div>
                        </div>
                        <div id="D2CodeIcon"></div>
                        <div id="D2CodeBottom">
                            <div class="D2CodeCornerLeft"></div>
                            <div class="D2CodeCornerRigth"></div>
                        </div>
                    </div>
                </div>
                <script>
                    if(true == logo_singtel)
                    {
                        document.write('<div id="headerRightProductName"><span class="HeaderSpanProduct">' + ProductName + '</span></div>');
                    }
                </script>
            </div>
        </div>
    </div>
    <div id="maincenter">
        <div id="MenuInfo"></div>
        <div id="SecondMenuInfo" class="Menuhide"></div>
        <div id="content">
            <iframe id="menuIframe" frameborder="0" width="100%" height="100%" marginheight="0" marginwidth="0" class="AspWidth" scrolling="no" overflow="hidden"></iframe>
        </div> 
    </div>

    <div id="fresh">
        <iframe frameborder="0" width="100%" height="100%" marginheight="0" marginwidth="0" scrolling="no" src="refresh.asp"></iframe>
    </div>
</div>
<div id="zhezhao"></div>
<div id="showcmode" style="display:none;">
    <h2 id="cmodetitle" > 
        <div id="cmtitlecontent"  BindText="mainpage019"></div>
        <div id="cmodeclose" ><img id="cmimageclose" src="../images/xx.png" onclick="hideCmodePage();"></div>
    </h2>
    
    <div id="cmodecontent" style="display:none;">

        <div id="apmode">
            <div id="apradiodiv" ><input id="2" type="radio" name="CMode" value="lan" /></div>
            <div id="cmimagediv" ><img id="appic" src="../images/apmode1.png"></div>
            <div id="apmodecontent" >
                <h2 id="upmodenames"><span id="apcontent" class="Smartinforight"  BindText="mainpage021" ></span></h2>
                <div id="cmexplain" BindText="mainpage025"></div>
            </div>
            <p id="hengline" ></p>
            <div class="clear"></div>
        </div>

        <div id="wifimode" >
            <div id="wifiradiodiv"><input id="3" type="radio" name="CMode" value="wifi" /></div>
            <div id="cmimagediv"><img id="wifipic" src="../images/Ranger1.png"></div>
            <div id="wifimodecontent">
                <h2 id="upmodenames"><span id="wificontent1" class="Smartinforight" BindText="mainpage022"></span></h2>
                <div id="cmexplain" BindText="mainpage026"></div>
            </div>
            <p id="hengline"></p>
            <div class="clear"></div>
        </div>

        <div id="rtmode" >
            <div id="rtradiodiv"><input id="1" type="radio" name="CMode" value="route" /></div>
            <div id="cmimagediv" class="cmpicdiv1" ><img id="rtpic" src="../images/router1.png"></div>
            <div id="rtmodecontent">
                <h2 id="upmodenames"><span id="rtcontent1" class="Smartinforight" BindText="mainpage020"></span></h2>
                <div id="cmexplain" BindText="mainpage027"></div>
            </div>
            <div class="clear"></div>
        </div>      
    </div>  
    <br>
    <div id="cmbutton" >
        <input type="button" id="MdyPwdcancel" class="CancleButtonCss buttonwidth_100px" onclick="hideCmodePage();" BindText="mainpage023" />
        <input type="button" id="MdyPwdApply" class="ApplyButtoncss buttonwidth_100px" onclick="showconfirm();" BindText="mainpage024" />   
        
    </div>
    
    <div class="alert_box" id="alert_box" style="display:none;">
        <div style="float:left;"><img id="reboot_img" src="../../../images/icon-thinking.gif" /></div>
        <div class="reboot_title_fir" style="float:left;margin-left:10px;" BindText="mainpage040"></div>
    </div>  
</div>

<div id="showcmode1" style="display:none;position:flex;top:50%;height:480px;margin-top:-190px;width:700px;left:50%;margin-left:-230px;background-color:white; z-index:1002;">
    <h2 id="cmodetitle1" style="width:100%;height:35px;background-color:#C4C8CC;margin-top:0px;font-size:16px;font-family: 微软雅黑;"> 
        <div id="cmtitlecontent"  BindText="mainpage019"></div>
        <div id="cmodeclose" ><img id="cmimageclose" src="../images/xx.png" onclick="hideCmodePage();"></div>
    </h2>
    <div id="aprepcontent" style="margin-top:4%;margin-left:2.5%;text-align:left;display:none;">
        <div id="rtmode" >
            <div id="rtradiodiv"><input id="5" type="radio" name="CMode" value="route" /></div>
            <div id="cmimagediv" class="cmpicdiv1" ><img id="rtpic5" src="../images/router1.png"></div>
            <div id="rtmodecontent">
                <h2 id="upmodenames"><span id="rtcontent" class="Smartinforight" BindText="mainpage020"></span></h2>
                <div id="cmexplain" BindText="mainpage027"></div>
            </div>
            <p id="hengline"></p>
            <div class="clear"></div>
        </div>
        <div id="wifimode" >
            <div id="wifiradiodiv"><input id="4" type="radio" name="CMode" value="wifi" /></div>
            <div id="cmimagediv"><img id="wifipic4" src="../images/Ranger1.png"></div>
            <div id="wifimodecontent">
                <h2 id="upmodenames"><span id="wificontent" class="Smartinforight" BindText="mainpage041"></span></h2>
                <div id="cmexplainrep" style="display:none;margin-top:5px;" BindText="mainpage026"></div>
                <div id="gcmexplainap" style="display:none;margin-top:5px;" BindText="mainpage025"></div>
                <div id="gcmexplainbridge" style="margin-top:-5px;width:600px;display:none;" BindText="mainpage042"></div>
            </div>
			<p id="hengline1" style="width:98%;height:1px;background-color:#CCCCCC;margin-top:20px;float:left;" ></p>
            <div class="clear"></div>
        </div>
		<div id="autoconsultguide" style="margin-top:30px;">
			<div id="autoconsultradio" style="float:left;margin-top:12px;"><input id="6" type="radio" name="CMode" value="autoconsult" /></div>
			<div id="cmimagediv" ><img id="autoadaptpic5" src="../../../images/apmode1.png"></div>
			<div id="apaumodecontent" style="margin-top:-11px;margin-left:72px;" >
				<h2 id="upmodenames" style=""><span id="autoconsultcontent" class="Smartinforight" BindText="mainpage043"></span></h2>
				<div id="autoconsultexplain" style="margin-top:-5px;width:600px;" BindText="mainpage044"></div>
			</div>
			<div class="clear"></div>
		</div>
		
    </div>
    
    <br>
    <div id="cmbutton1" style="margin-top:10px;">
        <input type="button" id="MdyPwdcancel" class="CancleButtonCss buttonwidth_100px" onclick="hideCmodePage();" BindText="mainpage023" />
        <input type="button" id="MdyPwdApply1" class="ApplyButtoncss buttonwidth_100px" onclick="showconfirm();" BindText="mainpage024" />       
    </div>
    
    <div class="alert_box1" id="alert_box1">
        <div style="float:left;"><img id="reboot_img" src="../../../images/icon-thinking.gif" /></div>
        <div class="reboot_title_fir" style="float:left;margin-left:10px;" BindText="mainpage040"></div>
    </div>  
</div>

<script type="text/javascript">
        function HWGetToken()
        {
            var tokenstring="";
            $.ajax(
            {
                type : "POST",
                async : false,
                cache : false,
                url : "/html/ssmp/common/GetRandToken.asp",
                success : function(data) 
                {
                    tokenstring = data;
                }
            });
            return tokenstring;
        }

	$(function(){
		showwifimode();
		$("input[name=CMode]").click(function(){
			showwifimode();
			if(autoadapt == 1)
			{
				if(($("input[name=CMode]:checked").attr("id")) == '4')
				{
					if(curChangeMode=='1')
					{
						document.getElementById("MdyPwdApply1").disabled=true;  
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
					}
					else
					{
						document.getElementById("MdyPwdApply1").disabled=false; 
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#56B2F8";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
						document.getElementById("MdyPwdApply1").style.Color = "#FFFFFF";
					}

				}
				if(($("input[name=CMode]:checked").attr("id")) == '5')
				{
					if(curChangeMode=='2' || curChangeMode=='3')
					{
						document.getElementById("MdyPwdApply1").disabled=true;  
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
					}
					else
					{
						document.getElementById("MdyPwdApply1").disabled=false; 
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#56B2F8";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
						document.getElementById("MdyPwdApply1").style.Color = "#FFFFFF";
					}
				}

			}
			else
			{
				if(($("input[name=CMode]:checked").attr("id")) == '4')
				{
					if(curChangeMode=='1' ||　(curChangeMode=='4' && adaptResult=='1'))
					{
						document.getElementById("MdyPwdApply1").disabled=false; 
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#56B2F8";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
						document.getElementById("MdyPwdApply1").style.Color = "#FFFFFF";
					}
					else
					{
						document.getElementById("MdyPwdApply1").disabled=true;  
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
					}

				}
				if(($("input[name=CMode]:checked").attr("id")) == '5')
				{
					if(curChangeMode=='2' || curChangeMode=='3' || (curChangeMode=='4' && adaptResult=='1'))
					{
						document.getElementById("MdyPwdApply1").disabled=false; 
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#56B2F8";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
						document.getElementById("MdyPwdApply1").style.Color = "#FFFFFF";
					}
					else
					{
						document.getElementById("MdyPwdApply1").disabled=true;  
						document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
						document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
					}
				}
			}
			if(($("input[name=CMode]:checked").attr("id")) == '6')
			{
				if(curChangeMode=='4')
				{
					document.getElementById("MdyPwdApply1").disabled=true;	
					document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
					document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
				}
				else
				{
					document.getElementById("MdyPwdApply1").disabled=false;	
					document.getElementById("MdyPwdApply1").style.backgroundColor = "#56B2F8";
					document.getElementById("MdyPwdApply1").style.borderColor = "#CCCCCC";
					document.getElementById("MdyPwdApply1").style.Color = "#FFFFFF";
				}
			}
		});
	});
	function showwifimode(){
		switch($("input[name=CMode]:checked").attr("id")){
			case "1":
			document.getElementById("MdyPwdApply").disabled=false;
			break;
			case "2":
			document.getElementById("MdyPwdApply").disabled=false;
			break;
			case "3":
			document.getElementById("MdyPwdApply").disabled=false;
			break;
			case "4":
			document.getElementById("MdyPwdApply1").disabled=false;					
			break;  
			case "5":
			document.getElementById("MdyPwdApply1").disabled=false;
			break;  
			case "6":
			document.getElementById("MdyPwdApply1").disabled=false;
			break;                                  
			default:break;
		}
	}
	
	function showconfirm()
	{
		if(($("input[name=CMode]:checked").attr("id"))=='1' || ($("input[name=CMode]:checked").attr("id"))=='2' || ($("input[name=CMode]:checked").attr("id"))=='3' || ($("input[name=CMode]:checked").attr("id"))=='4' || ($("input[name=CMode]:checked").attr("id"))=='5' || ($("input[name=CMode]:checked").attr("id"))=='6')
		{
			var cmbln = window.confirm(framedesinfo["mainpage028"]);
		}
		if (cmbln == true)
		{
			document.getElementById('alert_box').style.display = "block";
			document.getElementById('alert_box1').style.display = "block";

			document.getElementById('cmodetitle').style.display = "none";
			document.getElementById('cmodetitle1').style.display = "none";
			document.getElementById('cmodecontent').style.display = "none";
			document.getElementById('cmbutton').style.display = "none";
			document.getElementById('cmbutton1').style.display = "none";
			document.getElementById('aprepcontent').style.display = "none";
			if(AdaptExist == 0)
			{
				$("#alert_box1").css("margin-top", "150px");
			}
			ModeChangeState();
			document.getElementById("MdyPwdApply").disabled=true;
			document.getElementById("MdyPwdApply").style.backgroundColor = "#bbbbbb";
			document.getElementById("MdyPwdApply").style.borderColor = "#bbbbbb";
			document.getElementById("cmimageclose").disabled=true;
			document.getElementById("MdyPwdcancel").disabled=true;  
			document.getElementById("1").disabled=true; 
			document.getElementById("2").disabled=true; 
			document.getElementById("3").disabled=true; 
			document.getElementById("4").disabled=true;
			document.getElementById("5").disabled=true;
			document.getElementById("6").disabled=true;
		}
		else
		{   
			document.getElementById("MdyPwdApply").disabled=true;
			document.getElementById("MdyPwdApply").style.backgroundColor = "#bbbbbb";
			document.getElementById("MdyPwdApply").style.borderColor = "#bbbbbb";
			
			document.getElementById("MdyPwdApply1").disabled=true;
			document.getElementById("MdyPwdApply1").style.backgroundColor = "#bbbbbb";
			document.getElementById("MdyPwdApply1").style.borderColor = "#bbbbbb";
			document.getElementById("6").disabled=false;
			document.getElementById("5").disabled=false;
			document.getElementById("4").disabled=false;
			if(curChangeMode=='1')
			{
				document.getElementById("5").checked=true;
				document.getElementById("5").disabled=false;
			}
			else if(curChangeMode=='2' || curChangeMode=='3')
			{
				document.getElementById("4").checked=true;
				document.getElementById("4").disabled=false;
			}
			else if(curChangeMode=='4' )
			{
				document.getElementById("6").checked=true;
				document.getElementById("6").disabled=false;
			}
		}
	}
	function ModeChangeState()
	{
		if(($("input[name=CMode]:checked").attr("id"))=='1' || ($("input[name=CMode]:checked").attr("id"))=='5')
		{   
			curChangeMode = '1';
		}
		else if(($("input[name=CMode]:checked").attr("id"))=='2')
		{   
			curChangeMode = '2';
		}
		else if(($("input[name=CMode]:checked").attr("id"))=='3')
		{   
			curChangeMode = '3';
		}
		else if(($("input[name=CMode]:checked").attr("id"))=='4')
		{
			var PrevChangeMode = curChangeMode;
			if(3 == aprepeater)
			{
				curChangeMode = '2';
			}
			else if(8 == aprepeater)
			{
				curChangeMode = '3';
			}
			if(1 == aprepEnable && 4 == PrevChangeMode)
			{
				curChangeMode = '3';
			}
		}
		else if(($("input[name=CMode]:checked").attr("id"))=='6')
		{	
			curChangeMode = '4';
		}
		DiagnoseToken = HWGetToken();
		
		$.ajax({
                type : "POST",
                async : true,
                cache : false,
				data : "cmode=" + curChangeMode + "&x.X_HW_Token=" + DiagnoseToken,
				url : "apmodechange.cgi?&RequestFile=index.asp",
            	success : function(data) {			
                }
                });
	}   
	
	ParseBindTextByTagName(framedesinfo, "span", 1);
	ParseBindTextByTagName(framedesinfo, "td", 1);
	ParseBindTextByTagName(framedesinfo, "div", 1);
	ParseBindTextByTagName(framedesinfo, "input", 2);

</script>

</body>
<script type="text/javascript">         
var Firststr = '<div id="MenuFirstLineSpace"><div id="MenuFirstLineIcon"></div><div id="MenuFirstLineMid"></div><div id="MenuFirstLineSpaceborder"></div></div>';

var menulist = [];
var activeMenuId = null;

function stMenuData(id, path, level, defico, clickico, url, defchild)
{
    this.id         = id;
    this.path       = ((path == '') ? '' : (path + '.')) + id;
    this.level      = level;
    this.defico     = defico;
    this.clickico   = clickico;
    this.url        = url;
    this.defchild   = defchild;
    this.hasChild   = false;
}

function setLv1MenuStyle(id, flag, ifOnlyChangeStyle)
{
    var menu = menulist[id];

    if (flag)
    {
        //change menu style
        $("#"         + id).addClass("menuContentActive");
        $("#name_"    + id).addClass("menuContTitleActive");
        $("#pointer_" + id).addClass("menuContPointerActive");
        $("#icon_"    + id).css("background", "url( " + menu.clickico + ") no-repeat center");

        if ((ifOnlyChangeStyle != null) && (ifOnlyChangeStyle == "onlyshow"))
            return menu;

        //show default sub-menu
        if ((menu.defchild != menu.id) //default menu is not menu its self, activate sub-menu
            && menu.hasChild)
        {
            return setLv2MenuStyle(menu.defchild, flag); //activate default sub-menu;
        }
    }
    else
    {
        //change menu style
        $("#"         + id).removeClass("menuContentActive");
        $("#name_"    + id).removeClass("menuContTitleActive");
        $("#pointer_" + id).removeClass("menuContPointerActive");
        $("#icon_"    + id).css("background", "url( " + menu.defico + ") no-repeat center");
    }
    return menu;
}

function setLv2MenuStyle(id, flag, ifOnlyChangeStyle)
{
    var menu = menulist[id];
    var parentId = menu.path.split('.')[0];

    if (flag)
    {
        //change parent menu style
        setLv1MenuStyle(parentId, flag, "onlyshow");
        //change menu style of itself
        if (!menu.hasChild) $("#name_" + id).addClass("SecondMenuTitleActive");

        if ((ifOnlyChangeStyle != null) && (ifOnlyChangeStyle == "onlyshow"))
            return menu;

        //show default sub-menu
        if ((menu.defchild != menu.id) //default menu is not menu its self, activate sub-menu
            && menu.hasChild)
        {
            //change menu pointer style
            $("#pointer_" + id).removeClass("SecondMenuPointer");
            $("#pointer_" + id).addClass("SecondMenuPointerBlock");
            return setLv3MenuStyle(menu.defchild, flag); //activate default sub-menu;
        }
        else
        {
            //change menu pointer style
            $("#pointer_" + id).removeClass("SecondMenuPointerBlock");
            if (menu.hasChild)
                $("#pointer_" + id).addClass("SecondMenuPointer");
            else
                $("#pointer_" + id).addClass("SecondMenuNullPointer");
        }
    }
    else
    {
        //change menu style
        $("#name_" + id).removeClass("SecondMenuTitleActive");
        //change menu pointer style
        $("#pointer_" + id).removeClass("SecondMenuPointerBlock");
        if (menu.hasChild)
            $("#pointer_" + id).addClass("SecondMenuPointer");
        else
            $("#pointer_" + id).addClass("SecondMenuNullPointer");
    }
    return menu;
}

function setLv3MenuStyle(id, flag)
{
    var menu = menulist[id];

    if (id == "")
    {
        id="menuid_3";
    }

    if (flag)
    {
        var parentId = menu.path.split('.')[1];
        //change parent menu style
        setLv2MenuStyle(parentId, flag, "onlyshow");
        //change menu style
        $("#"+id).addClass("ThirdMenuTitleActive")
    }
    else
    {
        //change menu style
        $("#"+id).removeClass("ThirdMenuTitleActive")
    }
    return menu;
}

function activeMenuStyle(id)
{
    var menu = menulist[id];

    if (menu == null)
        return null;

    var ids = menu.path.split('.');
    switch(menu.level)
    {
        case 3:
            menu = setLv3MenuStyle(ids[2], true); //set style of lv3 menu and parent lv2 & lv1 menu
            break;
        case 2:
            menu = setLv2MenuStyle(ids[1], true); //set style of lv2 menu and parent lv1 menu, active default lv3 menu
            break;
        default:
            menu = setLv1MenuStyle(ids[0], true); //set style of lv1 menu style, active default lv2 or lv3 menu
            break;
    }
    return menu;
}

function deactiveMenuStyle(id)
{
    var menu = menulist[id];

    if (menu == null)
        return ;

    var ids = menu.path.split('.');
    switch(menu.level)
    {
        case 3:
            setLv3MenuStyle(ids[2], false); //reset lv3 menu style
        case 2:
            setLv2MenuStyle(ids[1], false); //reset lv2 menu style
        default:
            setLv1MenuStyle(ids[0], false); //reset lv1 menu style
    }
}

function changeCrossLvMenuStyle(oldId, newId)
{
    var oldMenu = menulist[oldId];
    var newMenu = menulist[newId];

    if ((oldMenu == null) || (newMenu == null)) //page loaded for the first time
        return;

    if (oldMenu.level == newMenu.level) //check whether its parent menu is the same or not
    {
        switch(oldMenu.level)
        {
            case 3:
                var lv2id_o = oldMenu.path.split('.')[1];
                var lv2id_n = newMenu.path.split('.')[1];
                if (lv2id_o != lv2id_n) //different parent, change lv3 menu list
                {
                    $("#" + lv2id_o + "_menu").addClass("Menuhide");
                    $("#" + lv2id_n + "_menu").removeClass("Menuhide");
                }
                else //same parent, change lv2 parent pointer style, because it has been deactivated
                {
                    $("#pointer_" + lv2id_n).removeClass("SecondMenuPointer");
                    $("#pointer_" + lv2id_n).addClass("SecondMenuPointerBlock");
                }
            case 2:
                var lv1id_o = oldMenu.path.split('.')[0];
                var lv1id_n = newMenu.path.split('.')[0];
                if (lv1id_o != lv1id_n)
                {
                    $("#" + lv1id_o + "_subMenus").addClass("Menuhide");
                    $("#" + lv1id_n + "_subMenus").removeClass("Menuhide");
                }
            default:
                break;
        }
    }
    else if (oldMenu.level < newMenu.level)
    {
        //change from upper level to lower level
        var lv1id_n = newMenu.path.split('.')[0];
        var lv1id_o = oldMenu.path.split('.')[0];

        //show lv2 menu list
        if (lv1id_o != lv1id_n)
            $("#" + lv1id_o + "_subMenus").addClass("Menuhide");
        $("#" + lv1id_n + "_subMenus").removeClass("Menuhide");
        $("#SecondMenuInfo").removeClass("Menuhide");
        $("#SecondMenuInfo").addClass("Menushow");
        if (newMenu.level > 2)
        {
            var lv2id = newMenu.path.split('.')[1];
            //show lv3 menu list
            $("#" + lv2id + "_menu").removeClass("Menuhide");
        }
        if (oldMenu.level < 2)
        {
            //collapse lv1 menu list
            expandFirstMenuTitle(false);
        }
    }
    else
    {
        //change from lower level to upper level
        if (oldMenu.level > 2)
        {
            var lv2id = oldMenu.path.split('.')[1];
            //hide lv3 menu list
            $("#"+lv2id+"_menu").addClass("Menuhide");
        }

        if (newMenu.level < 2)
        {
            var lv1id = oldMenu.path.split('.')[0];
            //hide lv2 menu list
            $("#" + lv1id + "_subMenus").addClass("Menuhide");
            $("#SecondMenuInfo").removeClass("Menushow");
            $("#SecondMenuInfo").addClass("Menuhide");
            //expand lv1 menu list
            expandFirstMenuTitle(true);
        }
        else
        {
            var lv1id_o = oldMenu.path.split('.')[0];
            var lv1id_n = newMenu.path.split('.')[0];
            if (lv1id_o != lv1id_n)
            {
                $("#" + lv1id_o + "_subMenus").addClass("Menuhide");
                $("#" + lv1id_n + "_subMenus").removeClass("Menuhide");
            }
        }
    }
}
function onMenuChange1(id,url)
{
    toggleQRCodeDisplay('none');

    if (!ifCanChangeMenu())
    {
        return;
    }

    if (activeMenuId != null)
    {
        deactiveMenuStyle(activeMenuId);
    }

    var menu = activeMenuStyle(id);

    changeCrossLvMenuStyle(activeMenuId, menu.id);

    if (menu != null)
        $("iframe#menuIframe").attr("src", url);

    activeMenuId = menu.id;
}

function onMenuChange(id)
{
    toggleQRCodeDisplay('none');

    if (!ifCanChangeMenu())
    {
        return;
    }

    if (activeMenuId != null)
    {
        deactiveMenuStyle(activeMenuId);
    }

    var menu = activeMenuStyle(id);

    changeCrossLvMenuStyle(activeMenuId, menu.id);

    if (menu != null)
        $("iframe#menuIframe").attr("src", menu.url);

    activeMenuId = menu.id;
}

function setParentDefchild(parentId, id)
{
    var menu = menulist[parentId];
    if ((menu != null)
        /*&& (menu.url == null)*/
        && (menu.defchild == parentId))
    {
        menu.defchild = id;
    }
}

/*create level-3 menus*/
function CreateThirdMenu(htmlTagId, parentId, parentPath, subMenus)
{
    var m3contain = document.getElementById(htmlTagId);

    for (var i in subMenus)
    {
        var id = subMenus[i].id;
        
        if(i == 0 && 1 == MenuModeVDF)
        {
            var m3title = document.createElement("div");
            m3title.id = id+"space";
            m3title.setAttribute('name',id+"strspace");
            m3title.className = "ThirdMenuTitleSpace";
            m3title.onclick = null;
            m3contain.appendChild(m3title);
        }

        menulist[id] = new stMenuData(id, parentPath, 3,
                                      subMenus[i].deficon,
                                      subMenus[i].clickicon,
                                      subMenus[i].url, id);
        
        var m3namesr = GetIdByUrl("m3div",subMenus[i].url);
        var m3title = document.createElement("div");
        m3title.id = id;
        //m3title.name = m3namesr;
        m3title.setAttribute('name',m3namesr);
        var Menu3NameStrValue = subMenus[i].name;

        m3title.className = "ThirdMenuTitle";

        
        m3title.onclick   = function(){ onMenuChange(this.id); }
        GetMenuTitle(subMenus[i].name, "third", m3title);
        var str = GetMenuStr(subMenus[i].name, "second");
        var txt = document.createTextNode(str.replace(/&nbsp;/g," "));
        m3title.appendChild(txt);
        m3contain.appendChild(m3title);

        if (i == 0)
        {
            setParentDefchild(parentId, id);
        }
    }
}

/*create level-2 menus*/
function CreateSecondMenu(parentId, parentPath, subMenus)
{
    var m2list = document.getElementById("SecondMenuInfo");
    var m2contain = document.createElement("div");
    
    m2contain.id = parentId + "_subMenus";
    m2contain.className = "Menuhide";
    m2list.appendChild(m2contain);

    for (var i in subMenus)
    {
        var id = subMenus[i].id;

        menulist[id] = new stMenuData(id, parentPath, 2,
                                      subMenus[i].deficon,
                                      subMenus[i].clickicon,
                                      subMenus[i].url, id);

        var m2namesr = GetIdByUrl("m2div",subMenus[i].url);
        var m2menu = document.createElement("div");
        //m2menu.name = m2namesr;
        m2menu.setAttribute('name',m2namesr); 
        m2menu.id = id;
        m2menu.className = "SecondmenuContent";
        m2menu.onclick   = function() { onMenuChange(this.id); }
        m2contain.appendChild(m2menu);
        var m2title = document.createElement("div");
        m2title.id = "name_"+id;
        var MenuNameStrValue = subMenus[i].name;
        if(1 == MenuModeVDF)
        {
            if(MenuNameStrValue.length > 22)
            {
                m2title.className = "SecondMenuTitleChangeLine";
            }
            else if(MenuNameStrValue.length > 20
                    && subMenus[i].subMenus != undefined)
            {
                m2title.className = "SecondMenuTitleChangeLine";
            }
            else
            {
                m2title.className = "SecondMenuTitle";
            }
        }
        else
        {
            m2title.className = "SecondMenuTitle";
        }
        
        GetMenuTitle(subMenus[i].name, "second", m2title);
        var str = GetMenuStr(subMenus[i].name, "second");
        var txt = document.createTextNode(str.replace(/&nbsp;/g," "));
        m2title.appendChild(txt);
        m2menu.appendChild(m2title);
        var m2pointer = document.createElement("div");
        m2menu.appendChild(m2pointer);
        m2pointer.id = "pointer_" + id;

        if (subMenus[i].subMenus != undefined)
        {
            m2pointer.className = "SecondMenuPointer";
            m2children = document.createElement("div");
            m2children.id = id + "_menu";
            m2children.className = "Menuhide";
            m2contain.appendChild(m2children);
            CreateThirdMenu(m2children.id, id, menulist[id].path, subMenus[i].subMenus);
            menulist[id].hasChild = true;
        }
        else
        {
            m2pointer.className = "SecondMenuNullPointer";
        }

        if (i == 0)
        {
            setParentDefchild(parentId, id);
        }
    }
}

/*create level-1 menus*/
for(var FirstMenuindex in menuJsonData)
{
    var m1namesr = GetIdByUrl("m1div",menuJsonData[FirstMenuindex].url);
    var id = menuJsonData[FirstMenuindex].id;
    Firststr += '<div class="menuContent" id=' + id + ' onclick="onMenuChange(this.id);">';

    Firststr +='<div class="FirstMenuIcon" id="icon_' + id + '" style="background: url(' + menuJsonData[FirstMenuindex].deficon + ') no-repeat center"></div>';
    Firststr +='<div class="menuContTitle" id="name_' + id + '" name="' + m1namesr + '"'+ GetMenuTitle(menuJsonData[FirstMenuindex].name, "first") + '>'
             + GetMenuStr(menuJsonData[FirstMenuindex].name, "first")
             + '</div>';
    Firststr +='<div class="menuContPointer menuContPointerdef" id="pointer_' + id + '"></div>';
    Firststr +='</div>';
    menulist[id] = new stMenuData(id, '', 1,
                                  menuJsonData[FirstMenuindex].deficon,
                                  menuJsonData[FirstMenuindex].clickicon,
                                  menuJsonData[FirstMenuindex].url, id);

    if(undefined != menuJsonData[FirstMenuindex].subMenus)
    {
        CreateSecondMenu(id, menulist[id].path, menuJsonData[FirstMenuindex].subMenus);
        menulist[id].hasChild = true;
    }
}
Firststr += '<div id="MenuBottomLineSpace"><div id="MenuBottomLineIcon"></div><div id="MenuBottomLineMid"></div><div id="MenuBottomLineSpaceborder"></div></div>';
$("#MenuInfo").append(Firststr);

ParseBindTextByTagName(framedesinfo, "span", 1);
ParseBindTextByTagName(framedesinfo, "div",  1);
document.getElementById('username').appendChild(document.createTextNode(UserName));

var UpgradeHeigthHandle = setInterval("adjustParentHeight();", 200);

var FirstclickExpansion = menuJsonData[0].id;
$("#" + FirstclickExpansion).trigger("click");

$("#AppDiv").click(function() {
    toggleQRCodeDisplay('auto');
});

$("#D2CodeIcon").click(function() {
    window.open(appUrl, "newwindow");
});

function getMenuStrDefLen(level)
{
    var length = 0;

    if (curLanguage.toUpperCase() == "CHINESE")
    {
        length = 8;
    }
    else if(curLanguage.toUpperCase() == "JAPANESE")
    {
        if (level == "first" )
        {
            length = 12;
        }
        else
        {
            length = 8;
        }
    }
    else
    {
        if (level == "first" )
        {
            length = 22;
        }
        else
        {
            length = 18;
        }
    }

    return length;
}

function GetMenuStr(datastr, level)
{
    if(1 == MenuModeVDF)
    {
        return datastr;
    }
    else
    {
        var length = getMenuStrDefLen(level);
        var MenuName = GetStringContentForTitle(datastr, length);
        return MenuName;
    }

}

function GetMenuTitle(datastr, level, element)
{
    if(1 == MenuModeVDF)
    {
        return;
    }
    
    var length = getMenuStrDefLen(level);
    var titlestr = "";
    if (datastr.length > length)
    {
        titlestr = ' title="' + datastr + '" ';
        if (element != null)
            element.setAttribute("title", datastr);
    }
    return titlestr;
}

function expandFirstMenuTitle(flag)
{
    var id;
    var action = ((flag == true) ? "block" : "none");

    $('#MenuFirstLineMid').css("display", action);
    $('#MenuBottomLineMid').css("display", action);

    for(var tmp in menulist)
    {
        if (menulist[tmp].level != 1) continue;
        id = "name_" + menulist[tmp].id;
        $('#' + id).css("display", action);
    }
}
</script>
</html>
