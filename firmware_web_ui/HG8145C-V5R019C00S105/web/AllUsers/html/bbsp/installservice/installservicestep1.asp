<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>install service step1</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<style>
.tabal_noborder_bg {
	padding:0px 0px 10px 0px;
	background-color: #FAFAFA;
}
</style>
<script language="JavaScript" type="text/javascript">
var AllWanInfo = GetWanList();
var iptvindex = -1;
var voipindex = -1;

function stLine(Domain, DirectoryNumber, Enable, PhyReferenceList )
{
    this.Domain = Domain;
    this.DirectoryNumber = DirectoryNumber;
	
    this.PhyReferenceList = PhyReferenceList;

    if (Enable.toLowerCase() == 'enabled')
    {
        this.Enable = 1;
    }
    else
    {
        this.Enable = 0;
    }     
	
    var temp = Domain.split('.');
    this.key = '.' + temp[7] + '.';
}

var AllLine = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.{i}.Line.{i},DirectoryNumber|Enable|PhyReferenceList,stLine);%>;

function getFirstIptvWanIndex()
{
	var idx = -1;
	for (var i = 0; i < AllWanInfo.length; i++)
	{ 
		if (AllWanInfo[i].Mode == 'IP_Routed' && AllWanInfo[i].ServiceList == 'IPTV' && AllWanInfo[i].IPv4Enable == '1' && AllWanInfo[i].IPv4AddressMode == 'Static')
		{
			idx = i;
			return idx;
		}
	}	   
    return idx;                          
}

function getFirstVoipWanIndex()
{
	var idx = -1;
	for (var i = 0; i < AllWanInfo.length; i++)
	{ 
		if (AllWanInfo[i].Mode == 'IP_Routed' && AllWanInfo[i].ServiceList == 'VOIP')
		{
			idx = i;
			return idx;
		}
	}	   
    return idx;                          
}

function SubmitReturn(val)
{
	val.id = 'ontidconfig';
	val.NameStr = 'ONT ID';
	val.name = '/CustomApp/devidconfig.asp';
	window.parent.OnChangeIframeShowPage(val); 
}

function SubmitNext(val)
{
	var addrtype = '';
	var srvtype = getSelectVal('SrvType');
	var voicesrv = getSelectVal('VoiceLineSrv');
	var valname = '/html/bbsp/installservice/installservicestep2.asp';
	if ('THREE' == srvtype.toUpperCase())
	{
		parent.ServiceConfigData.PurchasedSrv = 'THREE';
		addrtype = getSelectVal('AddrType');
		parent.ServiceConfigData.AddrType = addrtype;
		if (-1 != iptvindex)
		{
			window.parent.AddConfigParaToGlobeVar("x="+AllWanInfo[iptvindex].domain, "x.Enable=1");
		}
		
		if (('NONE' == addrtype.toUpperCase()) && ('NO' == voicesrv.toUpperCase()))
		{
			valname = '/CustomApp/SumaryConfig.asp';
		}
	}
	else if ('TWO' == srvtype.toUpperCase())
	{
		parent.ServiceConfigData.PurchasedSrv = 'TWO';
		parent.ServiceConfigData.AddrType = '';
		if (-1 != iptvindex)
		{
			window.parent.AddConfigParaToGlobeVar("x="+AllWanInfo[iptvindex].domain, "x.Enable=0");
		}
		
		if ('NO' == voicesrv.toUpperCase())
		{
			valname = '/CustomApp/SumaryConfig.asp';
		}
	}
	
	voipindex = getFirstVoipWanIndex();
	
	if('YES' == voicesrv.toUpperCase())
	{
		parent.ServiceConfigData.VoiceServiceEnable = installservice_language['bbsp_yes'].toUpperCase();
		window.parent.AddConfigParaToGlobeVar("z=InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1", "z.Enable=Enabled");
		if (-1 != voipindex)
		{
			window.parent.AddConfigParaToGlobeVar("n="+AllWanInfo[voipindex].domain, "n.Enable=1");
		}
	}
	else if ('NO' == voicesrv.toUpperCase())
	{
		parent.ServiceConfigData.VoiceServiceEnable = installservice_language['bbsp_no'].toUpperCase();;
		window.parent.AddConfigParaToGlobeVar("z=InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1", "z.Enable=Disabled");
		if (-1 != voipindex)
		{
			window.parent.AddConfigParaToGlobeVar("n="+AllWanInfo[voipindex].domain, "n.Enable=0");
		}
	}
	val.id = '';
	val.NameStr = 'Service selection';
	val.name = valname;
	window.parent.OnChangeIframeShowPage(val); 
}

function SrvTypeChange()
{
	var srvtype = getSelectVal('SrvType');
	if ('THREE' == srvtype.toUpperCase())
	{
		if(-1 != iptvindex)
		{
			setDisplay('AddrTypeRow',1);
		}
		else
		{
			 AlertEx(installservice_language['bbsp_creatwan']);
			 setSelect('SrvType','TWO');
			 return;
		}
	}
	else if ('TWO' == srvtype.toUpperCase())
	{
		setDisplay('AddrTypeRow',0);
	}
}

function setDataDisplay()
{
	var index = -1;
	index = getFirstIptvWanIndex();
	if (-1 != index)
	{
		iptvindex = index;
		parent.ServiceConfigData.domain = AllWanInfo[iptvindex].domain;
		if (1 == AllWanInfo[iptvindex].Enable)
		{
			setSelect('SrvType','THREE');
		}
		else
		{
			setSelect('SrvType','TWO');
		}
		if (1 == AllWanInfo[iptvindex].IPv4NATEnable)
		{
			setSelect('AddrType','Dynamic');
		}
		else
		{
			setSelect('AddrType','Static');
		}
	}
	else
	{
		setSelect('SrvType','TWO');
		setSelect('AddrType','None');
	}

	if((null != AllLine[0]) &&(1 == AllLine[0].Enable))
	{
		setSelect('VoiceLineSrv','yes');
	}
	else
	{
		setSelect('VoiceLineSrv','no');
	}
}

function LoadFrame()
{
	setDataDisplay();
	SrvTypeChange();
}
</script>
</head>
<body onLoad="LoadFrame();" class="iframebody"> 
<form id = "Step1ConfigForm">
<div id="FuctionPageArea" class="FuctionPageAreaCss">
<div id="FunctionPageTitle" class="FunctionPageTitleCss">
<span id="PageTitleText" class="PageTitleTextCss" BindText="bbsp_installservice_title"></span>
</div>
<div style="height:30px;"></div>
<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<li   id="SrvType"              RealType="DropDownList"       DescRef="bbsp_servicetype"      RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"     
InitValue="[{TextRef:'bbsp_three',Value:'THREE'},{TextRef:'bbsp_two',Value:'TWO'}]" ClickFuncApp="onchange=SrvTypeChange"/>
<li   id="AddrType"             RealType="DropDownList"       DescRef="bbsp_addrtype"      RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"     
InitValue="[{TextRef:'bbsp_dynamic',Value:'Dynamic'},{TextRef:'bbsp_static',Value:'Static'},{TextRef:'bbsp_none',Value:'None'}]"/>
<li   id="VoiceLineSrv"         RealType="DropDownList"       DescRef="bbsp_voiceline"      RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"     
InitValue="[{TextRef:'bbsp_yes',Value:'yes'},{TextRef:'bbsp_no',Value:'no'}]"/>
</table>
<script>
var TableClass = new stTableClass("PageSumaryTitleCss tablecfg_title width_per55", "tablecfg_right width_per45", "", "Select");
var Step1ConfigFormList = new Array();
Step1ConfigFormList = HWGetLiIdListByForm("Step1ConfigForm");
HWParsePageControlByID("Step1ConfigForm", TableClass, installservice_language, null);
</script>
<div style="height:30px;"></div>
</div>
</form>

<div style="height:30px;"></div>
<table width="100%" border="0" cellspacing="0" cellpadding="0" class=""> 
	<tr> 
	 <td class='width_per3'></td> 
	  <td class="table_submit" > 
	   <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
	   <button id="btnReturn" name="btnReturn" type="button" class="BluebuttonGreenBgcss width_120px" style="margin-left: 0px;" onClick="SubmitReturn(this);"><script>document.write(installservice_language['bbsp_return']);</script> </button> 
	   <button id="btnNext" name="btnNext" type="button" class="BluebuttonGreenBgcss width_120px" style="margin-left: 36px;" onClick="SubmitNext(this);"><script>document.write(installservice_language['bbsp_next']);</script> </button>  
	</tr> 
</table> 

<script>
	ParseBindTextByTagName(installservice_language, "span",  1);
	ParseBindTextByTagName(installservice_language, "td",    1);
	ParseBindTextByTagName(installservice_language, "input", 2);
</script>

</body>
</html>