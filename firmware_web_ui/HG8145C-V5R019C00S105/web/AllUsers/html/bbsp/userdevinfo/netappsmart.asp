<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<title>network application</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="javascript" src="../common/wan_control.asp"></script>
<script language="JavaScript" type="text/javascript">
var CurrentLang = '<%HW_WEB_GetCurrentLanguage();%>';

var numpara1 = "";
var numpara1 = "";
var porttype = "";
var portid   = "";
var page = 1;
var FltsecLevel = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Security.X_HW_FirewallLevel);%>'.toUpperCase();
var PccwFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_PCCW);%>';
var curUserType='<%HW_WEB_GetUserType();%>';
var sysUserType='0';
var curCfgModeWord ='<%HW_WEB_GetCfgMode();%>'; 

if(( window.location.href.indexOf("?") > 0) &&( window.location.href.split("?").length == 6))
{
	 numpara1 = window.location.href.split("?")[1];
	 numpara2 = window.location.href.split("?")[2];
	 porttype = window.location.href.split("?")[3];
	 portid   = window.location.href.split("?")[4];
	 page     = window.location.href.split("?")[5];	 
}

function loadlanguage()
{
	var all = document.getElementsByTagName("td");
	for (var i = 0; i <all.length ; i++) 
	{
		var b = all[i];
		if(b.getAttribute("BindText") == null)
		{
			continue;
		}
		b.innerHTML = userdevinfo_language[b.getAttribute("BindText")];
	}
}

function LoadFrame()
{
	if((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY"))
	{
		setDisplay('DivBtnipfilt',0);
	}
	if(FltsecLevel != 'CUSTOM')
	{
		setDisable('Value1' , 1);
	}
	loadlanguage();
}

function  onClickSubmit(string)
{
	window.parent.onMenuChange(string.id);
	
	if("ipincoming" == string.id)
	{
		window.location='../../../html/bbsp/ipincoming/ipincoming.asp?' + numpara1;
	}
	else if("macfilter" == string.id)
	{
		window.location='../../../html/bbsp/macfilter/macfilter.asp?' + numpara2;
	}
	else if("portmapping" == string.id)
	{
		window.location='../../../html/bbsp/portmapping/portmapping.asp?' + numpara1;
	}
	else if("dhcpstaticconfig" == string.id)
	{
		window.location = '../../../html/bbsp/dhcpstatic/dhcpstatic.asp?' + numpara1 + '?' + numpara2;
	}
}
</script>
</head>
<body  class="mainbody" onLoad="LoadFrame();"> 
<table width="100%" border="0" cellspacing="0" cellpadding="0" >
	<tr>
		<script>         
			document.write('<div id="DivBtnipfilt">');
			document.write('<button style="padding-left:px;text-align:left;" name="ipincoming" id="ipincoming"  type="button" class="NewDelbuttoncss" onClick="onClickSubmit(this);">'+ '&nbsp;');
			document.write(userdevinfo_language['bbsp_ipfilt']);
			document.write('</button>');
			document.write('<br />');
			document.write('</div>');
			document.write('<button style="padding-left:px;text-align:left;" name="macfilter" id="macfilter"  type="button" class="NewDelbuttoncss" onClick="onClickSubmit(this);">'+ '&nbsp;');
			document.write(userdevinfo_language['bbsp_macfilt']);
			document.write('</button>');
			document.write('<br />');

			document.write('<button style="padding-left:px;text-align:left;" name="portmapping" id="portmapping"  type="button" class="NewDelbuttoncss" onClick="onClickSubmit(this);">'+ '&nbsp;');
			document.write(userdevinfo_language['bbsp_poermap']);
			document.write('</button>');
			document.write('<br />');
	
			document.write('<button style="padding-left:px;text-align:left;" name="dhcpstaticconfig" id="dhcpstaticconfig"  type="button" class="NewDelbuttoncss" onClick="onClickSubmit(this);">'+ '&nbsp;');
			document.write(userdevinfo_language['bbsp_dhcpresipconfig']);
			document.write('</button>');
		</script>	
	</tr>
</table>
<table width="100%" height="30"> 
  <tr> 
    <td class='title_bright1'> <button id="back" name="back" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="window.location='userdevinfo.asp?'+page;" enable=true ><script>document.write(userdevinfo_language['bbsp_back']);</script></button> </td> 
  </tr> 
</table> 
</body>
</html>
