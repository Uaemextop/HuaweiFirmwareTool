<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1"><!-IE7 mode->
<meta http-equiv="Pragma" content="no-cache" />
<title></title>
<link href="/Cuscss/<%HW_WEB_GetCusSource(login.css);%>"  media="all" rel="stylesheet" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(frame.css);%>"  media="all" rel="stylesheet" />
<style type="text/css">
</style>
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
<script type="text/javascript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script id="langResource" language="JavaScript" src="/frameaspdes/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" type="text/javascript">
var FailStat ='<%HW_WEB_GetLoginFailStat();%>';
var LoginTimes = '<%HW_WEB_GetLoginFailCount();%>';
var ModeCheckTimes = '<%HW_WEB_GetModPwdFailCnt();%>';
var Var_DefaultLang = '<%HW_WEB_GetCurrentLanguage();%>';
var Language = Var_DefaultLang;
var LockTime = '<%HW_WEB_GetLockTime();%>';
var LockLeftTime = '<%HW_WEB_GetLeftLockTime();%>';
var errloginlockNum = '<%HW_WEB_GetTryLoginTimes();%>';
var locklefttimerhandle;
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var Var_LastLoginLang = '<%HW_WEB_GetLoginRequestLangue();%>';
var languageList = '<%HW_WEB_GetSPEC(SSMP_SPEC_WEB_LANGUAGE_SET.STRING);%>';
var APPVersion = '<%HW_WEB_GetAppVersion();%>';
var ProductType = '<%HW_WEB_GetProductType();%>';
var dev_uptime = '<%HW_WEB_GetOsUpTime();%>';
var Ssid1 = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID);%>';
var Ssid2 = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID);%>';

function SetUptime()
{
    dev_uptime ++;
    var second = parseInt(dev_uptime);
    var dd = parseInt(second/(3600*24));
    var hh = parseInt((second%(3600*24))/3600);
    var mm = parseInt((second%3600)/60);
    var ss = parseInt(second%60);
    var strtime = "";
    if (dd <= 1) {
        strtime += dd + " day ";
    } else {
        strtime += dd + " days ";
    }

    if (hh <= 1) {
        strtime += hh + " hour ";
    } else {
        strtime += hh + " hours ";
    }

    if (mm <= 1) {
        strtime += mm + " minute ";
    } else {
        strtime += mm + " minutes ";
    }

    if (ss <= 1) {
        strtime += ss + " second";
    } else {
        strtime += ss + " seconds ";
    }

    getElById("showtime").innerHTML = strtime;
}
function WANIP(domain, ConnectionStatus, ExternalIPAddress, X_HW_SERVICELIST, ConnectionType, AddressingType, IPv4Enable, IPv6Enable)
{
    this.domain = domain;
    this.ConnectionStatus = ConnectionStatus; 
    this.ConnectionType = ConnectionType; 
    if(ConnectionType == 'IP_Bridged') {
        this.ExternalIPAddress  = '--';
    } else {
        this.ExternalIPAddress  = ExternalIPAddress;
    }
    this.X_HW_SERVICELIST = X_HW_SERVICELIST;
    this.WanType = AddressingType;
    this.IPv4Enable = IPv4Enable;
    this.IPv6Enable = IPv6Enable;
}

function WANPPP(domain, ConnectionStatus, ExternalIPAddress, X_HW_SERVICELIST, ConnectionType, IPv4Enable, IPv6Enable)
{
    this.domain = domain;
    this.ConnectionStatus = ConnectionStatus;
    this.ConnectionType = ConnectionType;
    if (ConnectionType == 'PPPoE_Bridged') {
        this.ExternalIPAddress  = '--';
    } else {
        this.ExternalIPAddress= ExternalIPAddress;
    }    
    this.X_HW_SERVICELIST = X_HW_SERVICELIST;
    this.WanType = 'PPPoE';
    this.IPv4Enable = IPv4Enable;
    this.IPv6Enable = IPv6Enable;
}

var WanIp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i},ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|AddressingType|X_HW_IPv4Enable|X_HW_IPv6Enable,WANIP);%>;
var WanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i},ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_IPv4Enable|X_HW_IPv6Enable,WANPPP);%>;
var Wan = new Array();
var ipAddressValue = "";
function SpliceWanInfo()
{
    for (i=0, j=0; WanIp.length > 1 && j < WanIp.length - 1; i++,j++) {
        Wan[i]= WanIp[j];
    }
    
    for (j=0; WanPpp.length > 1 && j < WanPpp.length - 1; i++,j++) {
        Wan[i]= WanPpp[j];
    }
}

SpliceWanInfo();

for (i = 0; i < Wan.length; i++)
{
    if ((Wan[i].ConnectionType == "IP_Routed") && (Wan[i].ConnectionStatus=="Connected") && (Wan[i].X_HW_SERVICELIST.indexOf("INTERNET") != -1) && (Wan[i].IPv4Enable == "1")) {
        if (Wan[i].ExternalIPAddress != "") {
           ipAddressValue = Wan[i].ExternalIPAddress;
        }
        break;
    }
}

function dealDataWithFun(str) {
    if ((typeof str == 'string') && (str.indexOf('function') == 0)) {
        return Function('return (' + str + ')')()();
      }

    return str;
}
function stDeviceInfo(domain, SerialNumber, HardwareVersion, SoftwareVersion)
{
    this.domain = domain;
    this.SerialNumber = SerialNumber;
    this.HardwareVersion = HardwareVersion;
    this.SoftwareVersion = SoftwareVersion;
}
function stPhysicalMedium(domain, Name, Status) {
    this.domain = domain;
    this.Name = Name;
    this.Status = Status;
}

var deviceInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, SerialNumber|HardwareVersion|SoftwareVersion, stDeviceInfo);%>;
var usblist = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.StorageService.1.PhysicalMedium.{i}, Name|Status, stPhysicalMedium);%>;

function UserDeviceInfo(Domain, DevStatus, PortType) 
{
    this.Domain = Domain;
    this.DevStatus = DevStatus;
    this.PortType = PortType;
}

var allUserDevinfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.X_HW_UserDev.{i}, DevStatus|PortType, UserDeviceInfo);%>;
var onLineDev = [];
for (var index = 0; index < allUserDevinfo.length - 1; index++) {
    if ((allUserDevinfo[index].DevStatus.toUpperCase() == "ONLINE") && (allUserDevinfo[index].PortType.toUpperCase() == "ETH")) {
        onLineDev.push(allUserDevinfo[index]);
    }
}

function stWlan(domain,name,ssid)
{
    this.domain = domain;
    this.name = name;
    this.ssid = ssid;
}
var WlanInfo = new Array();
WlanInfo = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|SSID,stWlan,STATUS);%>;
function stAssociatedDevice(domain,X_HW_Uptime)
{
    this.domain = domain;
    this.X_HW_Uptime = X_HW_Uptime;
}
function stRadio(domain,OperatingFrequencyBand,Enable)
{
    this.domain = domain;
    this.OperatingFrequencyBand = OperatingFrequencyBand;
    this.Enable = Enable;
}
function getWlanInstFromDomain(domain)
{
    if (domain != '') {
        var array = domain.split('.');
        var str = array[4];
        return (parseInt(str));
    }
}

function getWlanPortNumber(portname)
{
    if (portname != '') {
        if (portname.length > 4) {
            return parseInt(portname.charAt(portname.length - 2) + portname.charAt(portname.length - 1));
        } else {
            return parseInt(portname.charAt(portname.length - 1));
        }
    }
}

AssociatedDevice = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.AssociatedDevice.{i}, X_HW_Uptime, stAssociatedDevice);%>;
var IspSSIDVisibility = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_ISPSSID_VISIBILITY);%>';
var Radio = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WiFi.Radio.{i},OperatingFrequencyBand|Enable,stRadio,EXTEND);%>;
var enbl2G = 0;
var enbl5G = 0;
if (Radio.length == 2) {
    enbl2G = Radio[0].Enable;   
    enbl5G = Radio[0].Enable;
} else if (['5GHz', '5G'].indexOf(Radio[0].OperatingFrequencyBand) >= 0) {
    enbl2G = Radio[0].Enable;   
    enbl5G = Radio[1].Enable;
} else if (['5GHz', '5G'].indexOf(Radio[0].OperatingFrequencyBand) >= 0) {
    enbl2G = Radio[1].Enable;   
    enbl5G = Radio[0].Enable;
}
var ssid2gNum = 0;
var ssid5gNum = 0;
var SsidPerBand = '<%HW_WEB_GetSPEC(AMP_SPEC_SSID_NUM_MAX_BAND.UINT32);%>';
var ssidStart2G = 0;
var ssidEnd2G = SsidPerBand - 1;
var ssidStart5G = SsidPerBand;
var ssidEnd5G = 2 * SsidPerBand -1;
for (i = 0; i < AssociatedDevice.length - 1; i++) {
    var ssidInst = getWlanInstFromDomain(AssociatedDevice[i].domain);
    for (j = 0; j < WlanInfo.length - 1; j++) {
        var ret = WlanInfo[j].domain.indexOf("InternetGatewayDevice.LANDevice.1.WLANConfiguration."+ ssidInst);
        if (ret == 0) {
            var wlanInst = getWlanInstFromDomain(WlanInfo[j].domain);
            var athindex = getWlanPortNumber(WlanInfo[j].name);
            if ((athindex >= ssidStart2G ) && (athindex <= ssidEnd2G)) {
                ssid2gNum ++;
            }

            if ((athindex >= ssidStart5G ) && (athindex <= ssidEnd5G)) {
                ssid5gNum ++;
            }
        }
    }
}

if (Var_LastLoginLang == '') {
    Language = Var_DefaultLang;
} else {
    Language = Var_LastLoginLang;
}

function GetLoginDes(DesId)
{
    return framedesinfo[DesId];
}

function showlefttime()
{
    if (LockLeftTime <= 0) {
        window.location="/login_degyptzvdf.asp";
        return;
    }

    var html = GetLoginDes("frame011") +  LockLeftTime + GetLoginDes(LockLeftTime == 1 ? "frame012a" : "frame012");
    SetDivValue("DivErrPromt", html);
    LockLeftTime = LockLeftTime - 1;
}

function setErrorStatus()
{
    clearInterval(locklefttimerhandle);
    if (((LoginTimes != null) && (LoginTimes != '') && (LoginTimes > 0))
        ||(FailStat == "1") || (ModeCheckTimes >= errloginlockNum)) {
        document.getElementById('DivErrPage').style.display = 'block';
    }

    if ((FailStat == "1") || (ModeCheckTimes >= errloginlockNum)) {
        if (ModeCheckTimes >= errloginlockNum) {
            SetDivValue("DivErrPromt", GetLoginDes("frame013a"));
        } else {
            SetDivValue("DivErrPromt", GetLoginDes("frame013"));
        }
        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);
        setDisable('loginbutton', 1);
    } else if (LoginTimes > 0 && LoginTimes < errloginlockNum) {
        SetDivValue("DivErrPromt", GetLoginDes("frame014"));
    } else if ((LoginTimes >= errloginlockNum) && (parseInt(LockLeftTime) > 0)) {
        var desc = "frame012";
        if (parseInt(LockLeftTime) == 1) {
            desc = "frame012a";
        }
        var html = GetLoginDes("frame011") +  LockLeftTime + GetLoginDes(desc);
        SetDivValue("DivErrPromt", html);
        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);
        setDisable('loginbutton', 1);
        locklefttimerhandle = setInterval('showlefttime()', 1000);
    } else {
        document.getElementById('DivErrPage').style.display = 'none';
    }
}

function setHtmlDslInfo(dslInfo)
{
    document.getElementById('upstreamcurrrate').innerHTML = dslInfo[0].UpstreamCurrRate;
    document.getElementById('downstreamcurrrate').innerHTML = dslInfo[0].DownstreamCurrRate;
    document.getElementById('upstreammaxrate').innerHTML = dslInfo[0].UpstreamMaxRate;
    document.getElementById('downstreammaxrate').innerHTML = dslInfo[0].DownstreamMaxRate;
}

function ShowDslInfo() {
    var dslInfo = new Array();
    $.ajax({
       type : "POST",
       async : false,
       cache : false,
        url : "/asp/getDslInfo.asp",
        success : function(data) {
            dslInfo = dealDataWithFun(data);
            setHtmlDslInfo(dslInfo);
        }
    });
}

function LoadFrame()
{
    SetUptime();
    setInterval("SetUptime();", 1000);
    ShowDslInfo();
    setInterval("ShowDslInfo();", 5000);
    if (ipAddressValue == "") {
        document.getElementById('internetstatus').style.display = '';
    } else {
        document.getElementById('connectduration').style.display = '';
    }
    document.getElementById('txt_Username').focus();
    clearInterval(locklefttimerhandle);
    onChangeLanguage();
    init();
}

function SetCusLanguageInfo(language, activflag)
{
    var node = document.getElementById(language);
    if ((null == node) || (undefined == node))
        return;

    var color = (activflag ? "#9b0000" : "#FFFFFF");
    node.style.color = color;
}

function init() {
    if (document.addEventListener) {
        document.addEventListener("keypress", onHandleKeyDown, false);
    } else {
        document.onkeypress = onHandleKeyDown;
    }
}

function onHandleKeyDown(event) {
    var e = event || window.event;
    var code = e.charCode || e.keyCode;
    if (code == 13) {
        LoginSubmit("loginbutton");
    }
}

function LoginSubmit(val)
{
    var Username = document.getElementById('txt_Username');
    var Password = document.getElementById('txt_Password');
    var appName = navigator.appName;
    var version = navigator.appVersion;
    var CheckResult = 0;

    if (appName == "Microsoft Internet Explorer") {
        var versionNumber = version.split(" ")[3];
        if (parseInt(versionNumber.split(";")[0]) < 6) {
            alert(GetLoginDes('frame006'));
            return false;
        }
    }

    if (Username.value == "") {
        alert(GetLoginDes("frame007"));
        Username.focus();
        return false;
    }

    if (Password.value == "") {
        alert(GetLoginDes("frame009"));
        Password.focus();
        return false;
    }

    var cookie = document.cookie;
    if (cookie != "") {
        var date = new Date();
        date.setTime(date.getTime() - 10000);
        var cookie22 = cookie + ";expires=" + date.toGMTString();
        document.cookie=cookie22;
    }
    var cnt;
    var Form = new webSubmitForm();
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        url : '/asp/GetRandCount.asp',
        success : function(data) {
            cnt = data;
        }
    });
    var Form = new webSubmitForm();
    var cookie2 = "Cookie=body:" + "Language:" + Language + ":" + "id=-1;path=/";
    Form.addParameter('UserName', Username.value);
    Form.addParameter('PassWord', base64encode(Password.value));
    Form.addParameter('Language', Language);
    document.cookie = cookie2;
    Username.disabled = true;
    Password.disabled = true;
    Form.addParameter('x.X_HW_Token', cnt);
    Form.setAction('/login.cgi');
    Form.submit();
    return true;
}

function onChangeLanguage(paralanguage)
{
    if (paralanguage != null) {
        if (Language == paralanguage) {
            return;
        }
        SetCusLanguageInfo(Language, false);
        Language = paralanguage;
    }
    var langSrc = "/frameaspdes/" + Language + "/ssmpdes.js";
    loadLanguage("langResource", langSrc, onLanguageChanged);
}

function onLanguageChanged()
{
    ParseBindTextByTagName(framedesinfo, "span",  1);
    ParseBindTextByTagName(framedesinfo, "div",   1);
    ParseBindTextByTagName(framedesinfo, "input", 2);
    SetCusLanguageInfo(Language, true);
    setErrorStatus();
}

function loadLanguage(id, url, callback)
{
    var docHead = document.getElementsByTagName('head')[0];
    var langScript = document.getElementById(id);
    if (langScript != null) {
        docHead.removeChild(langScript);
    }

    langScript = document.createElement('script');
    langScript.setAttribute('type', 'text/javascript');
    langScript.setAttribute('src', url);
    langScript.setAttribute('id', id);
    if (callback != null) {
        langScript.onload = langScript.onreadystatechange = function() {
            if (langScript.ready) {
                return false;
            }
            if ((!langScript.readyState) || (langScript.readyState == "loaded") || (langScript.readyState == 'complete')) {
                langScript.ready = true;
                callback();
            }
        };
    }
    docHead.appendChild(langScript);
}
</script>
</head>
<body onLoad="LoadFrame();">
<div id="base_mask" style=""></div>
<div id="main_wrapper">
	<div id="ausvocus_white_banner_bg" style="display:none;width:100%;height:49px;background:white;margin-bottom: -49px;"></div>
	<div id="loginarea">
		<div id="brandlog" style="display:none;"></div>
		<div id="ProductName"></div>
		<script>
			if(ProductType == '2') {
				document.write('<div id="welcomtext"><span class="welcometitle" id ="spanwelcomtext" BindText="frame004telmex"></span></div>');
			} else {
				document.write('<div id="welcomtext"><span class="welcometitle" id ="spanwelcomtext" BindText="frame004"></span></div>');
			}
		</script>
		<div id="logininfo">
			<div id="chooselag" class="changelanguageline" style="display:none;">
				<div class="changelanguageleft"></div>
				<div id="chooselagButton" class="changelanguageright"></div>
			</div>
			<div id="loginuser" class="contentItemlogin">
				<div class="labelBoxlogin"><span id="account" BindText="frame001"></span></div>
				<div class="contenboxlogin"><input type="text" id="txt_Username" name="txt_Username" class="logininputcss" /></div>
			</div>
			<div id="loginpwd" class="contentItemlogin">
				<div class="labelBoxlogin"><span id="Password" BindText="frame002"></span></div>
				<div class="contenboxlogin"><input type="password" autocomplete="off" id="txt_Password" name="txt_Password" class="logininputcss" autocomplete="off" /></div>
			</div>
			<div class="accordion" id="accordion_help">
				<div id="user_find" class="ember-view accordion-group">
					<div class="accordion-heading marginright_35"> 
						<div id="collapseinfo_1" class="text_center paddingright_15 index_page_font_color accordion-toggle text_underline">
							<span id="i18n-0" BindText="frame0161"></span>
						</div>
					</div>
					<div id="collapse_1" class="hide">
						<div class="accordion-inner">
							<div class="rounddiv getaccount_part">
								<div class="bodydiv rounddiv paddingtop_8 getaccount_part_body index_page_font_color" align="center"> &nbsp;&nbsp;&nbsp;
									<span id="i18n-1" BindText="frame017"></span>
								</div>
								<div class="bodydiv rounddiv getaccount_info paddingbottom_20" align="center">
									<div class="index_page_font_color text_left">
										<span id="i18n-2" BindText="frame018"></span>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div id="user_restore" class="ember-view accordion-group margintop_15">
					<div class="accordion-heading marginright_35">
						<div id="collapseinfo_2" class="text_center paddingright_15 index_page_font_color accordion-toggle text_underline">
							<span id="i18n-3" BindText="frame019"></span>
						</div>
					</div>
					<div id="collapse_2" class="hide">
						<div class="accordion-inner">
							<div class="rounddiv getaccount_part">
								<div class="bodydiv rounddiv paddingtop_8 getaccount_part_body index_page_font_color"> &nbsp;&nbsp;&nbsp;
									<span id="i18n-4" BindText="frame020"></span>
								</div>
								<div class="getaccount_info rounddiv">
									<div class="bodydiv rounddiv">
										<div class="text_left index_page_font_color" BindText="frame021">
										</div>
										<div class="text_left">
											<font color="#FF0000">
												<span id="i18n-5" BindText="frame022"></span>
											</font>
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
			<div id="loginbuttondiv" class="contentItemlogin">
				<div class="labelBoxlogin"></div>
				<div class="contenboxlogin"><input type="button" class="whitebuttonBlueBgcss buttonwidth_237px" id="loginbutton" onClick="LoginSubmit(this.id);" value="" BindText="frame003" /></div>
			</div>
			<div id="DivErrPage" class="contentItemlogin">
				<div id="DivErrPagePlace" class="labelBoxlogin"></div>
				<div id="DivErrIconPlace" class="contenboxlogin"><div id="DivErrIcon"></div><div id="DivErrPromt"></div></div>
			</div>
			<div class="func_spread"></div>
			<div id="statusinfo">
				<div class="width_100p info_title info_list text_left">
					<div id="index_show_status" class="paddingleft_5 paddingtop_3 paddingbottom_3 index_page_font_color statusinfo_bg">
						<span BindText="frame030_degyptzvdf"></span>
					</div>
					<div class="index_list_info_back_color width_100p">
				<hr class="table_list_bottom_line">
				<div class="index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr id="internetstatus" style="display:none;">
							<td><span BindText="frame031"></span></td>
							<td class="text_right paddingright_20 fontweight_thick" BindText="frame032"></td>
						</tr>
						<tr id="connectduration" style="display:none;">
							<td><span BindText="frame033"></span></td>
							<td class="text_right paddingright_20 fontweight_thick">
							<span id="showtime"></span>
							</td>
						</tr>
					</table>
				</div>
				<hr class="table_list_bottom_line">
				<div class="index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr>
							<td><span BindText="frame034"></span></td>
							<td id="index_wifi_number" class="text_right paddingright_20 fontweight_thick"><script>document.write(ssid2gNum);</script></td>
						</tr>
						<tr>
							<td><span BindText="frame035"></span></td>
							<td class="text_right paddingright_20 fontweight_thick"><span id="i18n-26">
								<script>
								var frequency2gFlag = "OFF";
								if (enbl2G == 1) {
									frequency2gFlag = "ON";
								}
								document.write(frequency2gFlag);
								</script></span>
							</td>
						</tr>
						<tr>
							<td><span BindText="frame036"></span></td>
							<td class="text_right paddingright_20 fontweight_thick"><script>document.write(Ssid1);</script></td>
						</tr>
						<tr>
							<td><span BindText="frame037"></span></td>
							<td id="index_wifi_number" class="text_right paddingright_20 fontweight_thick">
							<script>document.write(ssid5gNum);</script>
							</td>
						</tr>
						<tr>
							<td><span BindText="frame038"></span></td>
							<td class="text_right paddingright_20 fontweight_thick">
								<script>
								var frequency5gFlag = "OFF";
								if (enbl5G == 1) {
									frequency5gFlag = "ON";
								}
								document.write(frequency5gFlag);
								</script>
							</td>
						</tr>
						<tr>
							<td><span BindText="frame039"></span></td>
							<td class="text_right paddingright_20 fontweight_thick"><script>document.write(Ssid2);</script></td>
						</tr>
					</table>
				</div>
				<hr class="table_list_bottom_line">
				<div id="LanHostCountinfo" class="ember-view index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr>
							<td id="lan_device_countinfo"><span BindText="frame040"></span></td>
							<td id="lan_device_count" class="text_right paddingright_20 fontweight_thick"><script>document.write(onLineDev.length);</script></td>
						</tr>
						<tr>
							<td id="index_usb"><span BindText="frame041"></span></td>
							<td id="index_usb_number" class="text_right paddingright_20 fontweight_thick">
								<script>
									var usbOnline = [];
									var printerCount = 0;
									var printerName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_Printer.Name);%>';
									for (var i = 0; i < usblist.length - 1; i++) {
										if (usblist[i].Status.toUpperCase() == "ONLINE") {
											usbOnline.push(usblist[i]);
										}
									}
									if (printerName != "") {
										printerCount = 1;
									}
									var usbDevCount = usbOnline.length + printerCount;
									document.write(usbDevCount);
								</script>
							</td>
						</tr>
					</table>
				</div>
				<hr class="table_list_bottom_line">
				<div id="HardSoftVersioninfo" class="index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr>
							<td id="index_hardware"><span BindText="frame042"></span></td>
							<td id="index_hardware_info" class="text_right paddingright_20 fontweight_thick"><script>document.write(deviceInfos[0].HardwareVersion);</script></td>
						</tr>
						<tr>
							<td id="index_software"><span BindText="frame043"></span></td>
							<td id="index_software_info" class="text_right paddingright_20 fontweight_thick"><script>document.write(deviceInfos[0].SoftwareVersion);</script></td>
						</tr>
					</table>
				</div>
				<hr class="table_list_bottom_line">
				<div id="Wanipaddrinfo" class="ember-view index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr>
							<td id="index_wanipaddr"><span BindText="frame044"></span></td>
							<td id="index_wanipaddr_info" class="text_right paddingright_20 fontweight_thick">
							<script>document.write(ipAddressValue);</script>
							</td>
						</tr>
					</table>
				</div>
				<hr class="table_list_bottom_line">
				<div id="SerialNumberinfo" class="ember-view index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr>
							<td id="index_serialnumber"><span BindText="frame045"></span></td>
							<td id="index_serialnumber_info" class="text_right paddingright_20 fontweight_thick"><script>document.write(deviceInfos[0].SerialNumber);</script></td>
						</tr>
					</table>
				</div>
				<hr class="table_list_bottom_line">
				<div id="Bandwidthinfo" class="ember-view index_page_font_color text_left paddingtop_8 paddingleft_25 paddingbottom_5">
					<table class="width_100p index_page_font_color">
						<tr>
							<td id="index_upCurrRate"><span BindText="frame046"></span></td>
							<td id="index_upCurrRate_info" class="text_right paddingright_20 fontweight_thick">
								<span id="upstreamcurrrate"></span>
							</td>
						</tr>
						<tr>
							<td id="index_downCurrRate"><span BindText="frame047"></span></td>
							<td id="index_downCurrRate_info" class="text_right paddingright_20 fontweight_thick">
								<span id="downstreamcurrrate"></span>
							</td>
						</tr>
						<tr>
							<td id="index_upstreamMaxBitRate"><span BindText="frame048"></span></td>
							<td id="index_upstreamMaxBitRate_info" class="text_right paddingright_20 fontweight_thick">
								<span id="upstreammaxrate"></span>
							</td>
						</tr>
						<tr>
							<td id="index_downstreamMaxBitRate"><span BindText="frame049"></span></td>
							<td id="index_downstreamMaxBitRate_info" class="text_right paddingright_20 fontweight_thick">
								<span id="downstreammaxrate"></span>
							</td>
						</tr>
					</table>
				</div>
				</div>
				</div>
				<div id="copyrightinfo">
					<div id="copyrighttext"><span id="footer" BindText="frame015a"></span></div>
				</div>
			</div>
		</div>
	</div>
</div>
<script type="text/javascript">
$(document).ready(function(){
	$('#i18n-0').click(function(){
		$('#collapse_2').css("display","none");
		$('#collapse_1').toggle('fast',function(){
		});
	});
	$('#i18n-3').click(function(){
		$('#collapse_1').css("display","none");
		$('#collapse_2').toggle('fast');
	});
});
ParseBindTextByTagName(framedesinfo, "span",  1);
ParseBindTextByTagName(framedesinfo, "td",  1);
ParseBindTextByTagName(framedesinfo, "input", 2);
document.getElementById('brandlog').style.display = 'block';
$("#ProductName").text("Home Gateway");
</script>
</body>
</html>
