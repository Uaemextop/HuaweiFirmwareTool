<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>ACL</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="javascript" src="../common/userinfo.asp"></script>
<script language="javascript" src="../common/<%HW_WEB_CleanCache_Resource(page.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>

<script language="JavaScript" type="text/javascript">
var FltsecLevel = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Security.X_HW_FirewallLevel);%>'.toUpperCase();
var SingleFreqFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_SINGLE_WLAN);%>';
var DoubleFreqFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
var curUserType='<%HW_WEB_GetUserType();%>';
var CfgModeWord ='<%HW_WEB_GetCfgMode();%>'; 

function stAclInfo(domain,TelnetLanEnable,HTTPWifiEnable,TELNETWifiEnable)
{
	this.domain = domain;
	this.HttpWifiEnable = HTTPWifiEnable;
	this.TelnetWifiEnable = TELNETWifiEnable;
	this.TelnetLanEnable = TelnetLanEnable;
}

function IsOSKNormalUser()
{
	if ('OSK' == CfgModeWord.toUpperCase() && curUserType != '0')
	{
		return true;
	}
	else
	{
		return false;
	}
}

var aclinfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecAclInfos, InternetGatewayDevice.X_HW_Security.AclServices,TELNETLanEnable|HTTPWifiEnable|TELNETWifiEnable,stAclInfo);%>;  
var AclInfo = aclinfos[0];

function LoadFrame()
{
	setCheck('httpwifi',AclInfo.HttpWifiEnable);
	setCheck('telnetlan',AclInfo.TelnetLanEnable);
	setCheck('telnetwifi',AclInfo.TelnetWifiEnable);
      
	if( AclInfo.TelnetLanEnable == 0)
	{
	    setDisable('telnetwifi' , 1);
	}   
	if(parseInt(AclInfo.HttpLanEnable,10) == 0)
	{
	    setDisable('httpwifi' , 1);  
	}

	if(FltsecLevel != 'CUSTOM')
	{                
		setDisable('httpwifi', 1);
		setDisable('telnetwifi', 1);
		setDisable('telnetlan' , 1);
		
		setDisable('bttnApply' , 1);
		setDisable('cancelValue' , 1);
	}    
	
	if((IsAdminUser() == false) || IsE8cFrame())     		
	{              
	    setDisplay('lan_table', 0);    	    
	    setDisplay('telnetwifiRow', 0); 
	}
	else
	{
		setDisplay('lan_table', 1);    	    
	    setDisplay('telnetwifiRow', 1); 
	}
	
	if (true == IsOSKNormalUser())
    {
	    setDisplay('lan_table', 1);    	    
	    setDisplay('telnetwifiRow', 1); 
    }
	
	if(SingleFreqFlag != 1 && DoubleFreqFlag != 1)
	{ 
		setDisplay('wifi_table', 0);   
	} 
}

function FormCheck()
{
	if((AclInfo.HttpWifiEnable != getCheckVal('httpwifi'))&&(0 == getCheckVal('httpwifi')))
	{
		if(false == ConfirmEx(acl_language['bbsp_confirm_wifi']))
		{
			setCheck('httpwifi',1);
			return false;
		}
	}
	return true;
}

function SubmitForm()
{
	if(false == FormCheck())
    {
        return;
    }

	setDisable('btnApply', 1);
    setDisable('cancelValue', 1);

    var Form = new webSubmitForm();
    Form.usingPrefix('x');
	
	if(((IsAdminUser() == true) && !IsE8cFrame())
			|| (true == IsOSKNormalUser()))
	{
		Form.addParameter('TELNETLanEnable',getCheckVal('telnetlan'));
		Form.addParameter('HTTPWifiEnable',getCheckVal('httpwifi'));	
		Form.addParameter('TELNETWifiEnable',getCheckVal('telnetwifi'));
	}
	else
	{ 
		 Form.addParameter('HTTPWifiEnable',getCheckVal('httpwifi')); 
	}
    Form.endPrefix();		
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_Security.AclServices&RequestFile=html/bbsp/acl/aclsmart.asp');	
	Form.submit();			
	setDisable('bttnApply',1);
    setDisable('cancelValue',1);  
}

function ChangeLevel(level)
{
	 
}

function CancelConfig()
{
    LoadFrame();
}
</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<script language="JavaScript" type="text/javascript">
if (('PTVDF' == CfgModeWord.toUpperCase()) || ('PTVDF2' == CfgModeWord.toUpperCase()))
{
	HWCreatePageHeadInfo("acltitle", GetDescFormArrayById(acl_language, "bbsp_mune"), GetDescFormArrayById(acl_language, "bbsp_title_prompt1"), false);
}
else
{
	HWCreatePageHeadInfo("acltitle", GetDescFormArrayById(acl_language, "bbsp_mune"), GetDescFormArrayById(acl_language, "bbsp_title_prompt"), false);
}
</script>
<div class="title_spread"></div>

<form id="lan_table" style="display:none;"> 
	<div id="LanServiceTitle" class="func_title" BindText="bbsp_table_lan"></div>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
		<li   id="telnetlan"   RealType="CheckBox"  DescRef="bbsp_table_lantel"   RemarkRef="Empty"   ErrorMsgRef="Empty"    Require="FALSE"    BindField="x.TELNETLanEnable"  InitValue="" />
	</table>
	<script>
		var TableClass = new stTableClass("per_35_52", "per_65_48", "ltr");
		var LanServiceFormList = new Array();
		LanServiceFormList = HWGetLiIdListByForm("lan_table",null);
		HWParsePageControlByID("lan_table",TableClass,acl_language,null);
	</script>
	<div class="func_spread"></div>
</form> 

<form id="wifi_table" style="display:block;"> 
	<div id="WlanServiceTitle" class="func_title" BindText="bbsp_table_wifi"></div>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
		<li   id="httpwifi"     RealType="CheckBox"  DescRef=""   RemarkRef="Empty"   ErrorMsgRef="Empty"    Require="FALSE"    BindField="x.HTTPWifiEnable"  InitValue="" />
		<li   id="telnetwifi"   RealType="CheckBox"  DescRef="bbsp_table_wifitelnet"   RemarkRef="Empty"   ErrorMsgRef="Empty"    Require="FALSE"    BindField="x.TELNETWifiEnable"  InitValue="" />
	</table>
	<script>
		var WlanServiceFormList = new Array();
		WlanServiceFormList = HWGetLiIdListByForm("wifi_table",null);
		HWParsePageControlByID("wifi_table",TableClass,acl_language,null);
		if (('PTVDF' == CfgModeWord.toUpperCase()) || ('PTVDF2' == CfgModeWord.toUpperCase()))
		{
			setNoEncodeInnerHtmlValue("httpwifiColleft", acl_language['bbsp_table_wifihttp1']);
		}
		else
		{
			setNoEncodeInnerHtmlValue("httpwifiColleft", acl_language['bbsp_table_wifihttp']);
		}
	</script>
</form> 

<table class="table_button" width="100%"> 
  <tr>
	<td class='width_per35'></td> 
	<td class="table_submit width_per65">
	<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
	 <button id="bttnApply" name="bttnApply" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="SubmitForm();" id="Button1"><script>document.write(acl_language['bbsp_app']);</script></button>
	  <button name="cancelValue" id="cancelValue" type="button" class="CancleButtonCss buttonwidth_100px" onClick="CancelConfig();"><script>document.write(acl_language['bbsp_cancel']);</script></button></td> 
  </tr> 
</table>
<div class="func_spread"></div>
<script>
	ParseBindTextByTagName(acl_language, "td",    1);
	ParseBindTextByTagName(acl_language, "div",   1);
</script>
</body>
</html>
