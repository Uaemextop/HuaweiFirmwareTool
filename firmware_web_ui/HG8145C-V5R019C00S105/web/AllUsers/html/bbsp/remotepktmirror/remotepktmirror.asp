<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>Remote package mirror</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../../bbsp/common/topoinfo.asp"></script>
<style>
.TextBox
{
	width:150px;  
}
#direction,#interface{
	width:81px;
}
</style>
<script language="JavaScript" type="text/javascript">
var MirrorStart = '<%HW_WEB_GetPackageActionFlag();%>';
var supportTelmex = "<%HW_WEB_GetFeatureSupport(BBSP_FT_TELMEX);%>";
var UpgradeFlag = 0;
var STBPort = '<%HW_WEB_GetSTBPort();%>';
var CurrentBin = '<%HW_WEB_GetBinMode();%>';
var IponlyFlg ='<%HW_WEB_GetFeatureSupport(HW_AMP_FT_IPONLY);%>';
var TianYiFlag = '<%HW_WEB_GetFeatureSupport(FT_AMP_ETH_INFO_TIANYI);%>';
function isPortInAttrName()
{
    if((1 == TianYiFlag) && ('E8C' == CurrentBin.toUpperCase()))
	{
		return true;
	}
	return false;
}
function GeInfo(Domain,Status)
{   
    this.Domain = Domain;
    this.Status = Status;
}

var GeInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig,Link,GeInfo);%>;
function stWlanWifi(domain,name,ssid)
{
    this.domain = domain;
    this.name = name;
    this.ssid = ssid;

}
function stClassificationArr(domain,ClassInterface,X_HW_Mirror,X_HW_Dircetion)
{
    this.domain = domain;
    this.ClassInterface = ClassInterface;
    this.X_HW_Mirror = X_HW_Mirror;
	this.X_HW_Dircetion = X_HW_Dircetion;

}


var WlanWifiArr = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|SSID,stWlanWifi);%>;

var ClassificationArr = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.QueueManagement.Classification.{i},ClassInterface|X_HW_Mirror|X_HW_Dircetion,stClassificationArr);%>;


function OnStartMirror()
{
    var SourceIPAddr = getValue("SIPAddress");
    var DestIPAddr = getValue("DIPAddress");
    var DirectionValue = getSelectVal("direction");
    var InterfaceValue = getSelectVal("interface");
	
	if ((SourceIPAddr.length == 0) || (isValidIpAddress(SourceIPAddr) == false))
	{
		AlertEx(remotepktcap_language['bbsp_srcinvalid']);
        return false;
	}
	
    if ((DestIPAddr.length == 0) || (isValidIpAddress(DestIPAddr) == false))
    {
        AlertEx(remotepktcap_language['bbsp_dstinvalid']);
        return false;
    }
    
    setDisable("ButtonStart", "1");
	setDisable("direction", "1");
	setDisable("interface", "1");
    var Form = new webSubmitForm();
	
	Form.addParameter('x.sip', SourceIPAddr);
	Form.addParameter('x.dip', DestIPAddr);
	switch(DirectionValue)
	{
		case 'ALL':
			Form.addParameter('y.X_HW_Dircetion', 'inbound');
			Form.addParameter('z.X_HW_Dircetion', 'outbound');
			if(InterfaceValue == 'ALL')
			{
				Form.addParameter('y.ClassInterface', '');
				Form.addParameter('y.X_HW_Mirror', 1);
				Form.addParameter('z.ClassInterface', '');
				Form.addParameter('z.X_HW_Mirror', 1);

			}
			else
			{
				Form.addParameter('y.ClassInterface', InterfaceValue);
				Form.addParameter('y.X_HW_Mirror', 1);
				Form.addParameter('z.ClassInterface', InterfaceValue);
				Form.addParameter('z.X_HW_Mirror', 1);
				
			}
			break;
		case 'outbound':
			Form.addParameter('y.X_HW_Dircetion', 'outbound');
			if(InterfaceValue == 'ALL')
			{
				Form.addParameter('y.ClassInterface', '');
				Form.addParameter('y.X_HW_Mirror', 1);
			}
			else
			{
				Form.addParameter('y.ClassInterface',InterfaceValue);
				Form.addParameter('y.X_HW_Mirror', 1);
			}
			break;
		case 'inbound':
			Form.addParameter('y.X_HW_Dircetion', 'inbound');
			if(InterfaceValue == 'ALL')
			{
				Form.addParameter('y.ClassInterface', '');
				Form.addParameter('y.X_HW_Mirror', 1);
			}
			else
			{
				Form.addParameter('y.ClassInterface', InterfaceValue);
				Form.addParameter('y.X_HW_Mirror', 1);
				
			}		
			break;
		default:
			break;
	}
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	if(DirectionValue == 'ALL')
	{
		Form.setAction('startmirpkgaction.cgi?'+'x=InternetGatewayDevice.X_HW_DEBUG.BBSP.QosMirror'
						+'&y=InternetGatewayDevice.QueueManagement.Classification'
						+'&z=InternetGatewayDevice.QueueManagement.Classification'
						+'&RequestFile=html/bbsp/remotepktmirror/remotepktmirror.asp');   
    }
	else
	{
		Form.setAction('startmirpkgaction.cgi?'+'x=InternetGatewayDevice.X_HW_DEBUG.BBSP.QosMirror'
									  +'&y=InternetGatewayDevice.QueueManagement.Classification'
									  +'&RequestFile=html/bbsp/remotepktmirror/remotepktmirror.asp');   
	}
	Form.submit(); 
}

function OnStopMirror()
{
    if (MirrorStart != '1')
    {
        return;
    }

    var Form = new webSubmitForm();
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));

    Form.setAction('stopmirpkgaction.cgi?RequestFile=html/bbsp/remotepktmirror/remotepktmirror.asp');   
    Form.submit(); 
}
var TableClass = new stTableClass("table_title width_per25", "table_right", "", "Select");

function LoadFrame()
{
    if (MirrorStart == '1')
    {
        setDisable("ButtonStart", "1");
		setDisable("direction", "1");
		setDisable("interface", "1");
		
		setNoEncodeInnerHtmlValue("currentstatus", ("<B><FONT class='color_red'>" + remotepktcap_language['bbsp_caping'] + "</FONT><B>"));
    }
	else
	{
		setNoEncodeInnerHtmlValue("currentstatus", ("<B><FONT class='color_red'>" + remotepktcap_language['bbsp_stop'] + "</FONT><B>"));
	}

    var all = document.getElementsByTagName("td");
    for (var i = 0; i <all.length ; i++) 
    {
		var b = all[i];
		if(b.getAttribute("BindText") == null)
		{
			 continue;
		}
		setObjNoEncodeInnerHtmlValue(b, remotepktcap_language[b.getAttribute("BindText")]);
    }
	var MirrorIndex = 0;
	for (var i = 0; i <ClassificationArr.length -1  ; i++) 
	{
		
		if("1" == ClassificationArr[i].X_HW_Mirror &&  "" != ClassificationArr[i].ClassInterface)
		{
			setSelect("interface", ClassificationArr[i].ClassInterface); 
		}
		if("1" == ClassificationArr[i].X_HW_Mirror)
		{
			MirrorIndex ++;
			setSelect("direction", ClassificationArr[i].X_HW_Dircetion);
		}
		
		if(2 == MirrorIndex ||  0 == MirrorStart)
		{
			setSelect("direction", "ALL");
		}
	}
}
function InitDirection()
{

   	var DirectionList = getElementById('direction');
	DirectionList.options.add(new Option(remotepktcap_language['bbsp_all'], 'ALL'));
	DirectionList.options.add(new Option(remotepktcap_language['bbsp_egress'], 'outbound'));
	DirectionList.options.add(new Option(remotepktcap_language['bbsp_ingress'], 'inbound'));
}

function LanName2LanDomain(LanName)
{
    if(LanName.length == 0)
    {
        return '';
    }
     
    var EthID = LanName.charAt(LanName.length - 1);
    return  "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig." + EthID;
}

var WifiSSIDInfoList = new Array();
function stWifiSSIDInfo(SSIDName,SSIDDomain)
{
    this.SSIDName = SSIDName;
	this.SSIDDomain = SSIDDomain;
}

function InitInterface()
{
	var InterfaceList = getElementById('interface');
	var SSIDInst;
	var LANInst;
    
	InterfaceList.options.add(new Option(remotepktcap_language['bbsp_all'], 'ALL'));

	for(var i=0; i< WlanWifiArr.length -1 ; i++)
	{
		SSIDInst= GetSSIDNameByDomain(WlanWifiArr[i].domain);
		WifiSSIDInfoList.push(new stWifiSSIDInfo(SSIDInst, GetSSIDDomainByName(SSIDInst)));
	}
	
	if(WifiSSIDInfoList.length > 1)
	{
		WifiSSIDInfoList.sort(function(a,b){
		return a.SSIDName.localeCompare(b.SSIDName);
		});
	}
	
	for(var i=0; i< WifiSSIDInfoList.length ; i++)
	{
		InterfaceList.options.add(new Option(WifiSSIDInfoList[i].SSIDName, WifiSSIDInfoList[i].SSIDDomain));
	}
	
	for(var i=0,j=1; i < GeInfos.length -1 ; i++,j++)
	{
		if(GeInfos[i].Status == "1")
		{
			if(isPortInAttrName())
			{
				LANInst= getTianYilandesc(j);
			}
			else
			{
				LANInst= 'LAN' + j;
			}
			if ((2 == j) && (4 == GeInfos.length - 1) && ('E8C' == CurrentBin.toUpperCase()) && (0 == STBPort))
			{
				LANInst = "iTV";
			}
			if ((5 == j) && ('1' == IponlyFlg))
			{
				LANInst = "EXT1";
			}
			if(j == STBPort)
			{
				LANInst = remotepktcap_language['bbsp_stb']; 
			}	
			InterfaceList.options.add(new Option(LANInst, LanName2LanDomain('LAN' + j)));
		}
	}
}
</script>
</head>
<body  class="mainbody" onLoad="LoadFrame();"> 
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("remotepkmirror", GetDescFormArrayById(remotepktcap_language, "bbsp_mune"), GetDescFormArrayById(remotepktcap_language, "bbsp_remotepktcap_title1"), false);
</script>
<div class="title_spread"></div>

<form id="ConfigForm" style="display:block">
<table border="0" cellpadding="0" cellspacing="0"  width="100%">
<li   id="currentstatus" RealType="HtmlText" DescRef="bbsp_state"        RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="FALSE"    BindField="CurrentStatus"   InitValue="Empty"/>
<li   id="SIPAddress"    RealType="TextBox"  DescRef="bbsp_sourceip"     RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="TRUE"    BindField="x.SourceIPAddr"  InitValue="Empty" />                                                                   
<li   id="DIPAddress"    RealType="TextBox"  DescRef="bbsp_desip"        RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="TRUE"    BindField="x.DestIPAddr"  InitValue="Empty"/>
<li   id="direction"    RealType="DropDownList"  DescRef="bbsp_direction"        RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="TRUE"    BindField="Empty"  InitValue="Empty"/>
<li   id="interface"    RealType="DropDownList"  DescRef="bbsp_interface"        RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="TRUE"    BindField="Empty"  InitValue="Empty"/>                                                                    
</table>
<script>
MirrorConfigFormList = HWGetLiIdListByForm("ConfigForm");
HWParsePageControlByID("ConfigForm", TableClass, remotepktcap_language, null);
InitDirection();
InitInterface();
</script>
<table cellpadding="0" cellspacing="0"  width="100%" class="table_button"> 
<tr> 
  <td class='width_per25'></td> 
  <td class="table_submit">
	<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
	<button name="ButtonStart" id="ButtonStart" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="OnStartMirror();"><script>document.write(remotepktcap_language['bbsp_startmirror']);</script></button>
	<button name="cancelValue" id="cancelValue" type="button" class="CancleButtonCss buttonwidth_100px" onClick="OnStopMirror();"><script>document.write(remotepktcap_language['bbsp_stopmirror']);</script></button> </td> 
</tr>
</table>

<script>
	if("1" == supportTelmex)
	{
		document.write("\<div id=\"fresh\" style=\"display:none\"\> ");
		document.write(" \<iframe frameborder=\"0\" height=\"100\%\" marginheight=\"0\" marginwidth=\"0\" scrolling=\"no\" src=\"../../../../refresh.asp\" width=\"100%\"\>\</iframe\> \</div\> ");
	}
</script>
</form>  
</body>
</html>
