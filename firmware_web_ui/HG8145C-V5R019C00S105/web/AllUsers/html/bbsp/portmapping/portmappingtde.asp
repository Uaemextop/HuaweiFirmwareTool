<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="Javascript" src="../common/portfwdprohibit.asp"></script>
<title>Portmapping</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" type="text/javascript">
var INVALID_WAN_ID = 255;
var enblPortList = new Array();
var oldPmList = new Array();
var fileUrl = 'html/bbsp/portmapping/portmappingtde.asp';

var numpara = "";
var AllowEditFlag = false;
if( window.location.href.indexOf("?") > 0)
{
    numpara = window.location.href.split("?")[1]; 
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
		setObjNoEncodeInnerHtmlValue(b, portmapping_language[b.getAttribute("BindText")]);
	}
}

function filterWan(WanItem)
{
	if (!(WanItem.Tr069Flag == '0' && (IsWanHidden(domainTowanname(WanItem.domain)) == false)))
	{
		return false;	
	}
    
	return true;
}

var WanInfo = GetWanListByFilter(filterWan);
function stPortMap(domain,ProtMapEnabled,RemoteHost,ExternalPort,ExternalPortEndRange,InternalPort,Protocol,InClient,Description)
{
    this.domain = domain;
    this.ProtMapEnabled = ProtMapEnabled;
    this.RemoteHost = RemoteHost;
	this.ExternalPort = ExternalPort;
	this.ExternalPortEndRange = ExternalPortEndRange;
	this.InternalPort = InternalPort;
	this.Protocol = Protocol;
    this.InClient = InClient;	
    this.Description = Description;
    var index = domain.lastIndexOf('PortMapping');
    this.Interface = domain.substr(0,index - 1);
}

function FormatPortStr(port)
{
    var portList = port.split(':');
    if ((portList.length > 1) && (parseInt(portList[1], 10) == 0))
    {
        return portList[0];
    }

    return port;
}

function ParsePortStart(port)
{
	var portList = FormatPortStr(port).split(':');
	var StartPort = portList[0];
	var EndPort = portList[0];
	if(portList.length > 1){
		EndPort = portList[1];
	}
	
	return StartPort;
}

function ParsePortEnd(port)
{
	var portList = FormatPortStr(port).split(':');
	var StartPort = portList[0];
	var EndPort = portList[0];
	if(portList.length > 1){
		EndPort = portList[1];
	}
	
	return EndPort;
}

var WanIPPortMapping = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaArrayPortMapping, InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i}.PortMapping.{i},PortMappingEnabled|RemoteHost|ExternalPort|ExternalPortEndRange|InternalPort|PortMappingProtocol|InternalClient|PortMappingDescription,stPortMap);%>;
var WanPPPPortMapping = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaArrayPortMapping, InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i}.PortMapping.{i},PortMappingEnabled|RemoteHost|ExternalPort|ExternalPortEndRange|InternalPort|PortMappingProtocol|InternalClient|PortMappingDescription,stPortMap);%>; 

function FindWanInfoByPortMapping(portMappingItem)
{
	var wandomain_len = 0;
	var temp_domain = null;
	
	for(var k = 0; k < WanInfo.length; k++ )
	{
		wandomain_len = WanInfo[k].domain.length;
		temp_domain = portMappingItem.domain.substr(0, wandomain_len);
		
		if (temp_domain == WanInfo[k].domain)
		{
			return WanInfo[k];
		}
	}
	return false;
}

var PortMapping = new Array();
var Idx = 0;
for (var i = 0; i < WanIPPortMapping.length-1; i++)
{
	if(WanIPPortMapping[i].InClient=="")
	{
		continue;
	}
	if(false == FindWanInfoByPortMapping(WanIPPortMapping[i]))
	{
		continue;
	}
	var tmpWan = FindWanInfoByPortMapping(WanIPPortMapping[i]);
    if (tmpWan.ServiceList != 'TR069'
       && tmpWan.ServiceList != 'VOIP'
       && tmpWan.ServiceList != 'TR069_VOIP'
       && tmpWan.Mode == 'IP_Routed')
	{    
	    PortMapping[Idx] = WanIPPortMapping[i];
		PortMapping[Idx].Interface = MakeWanName(tmpWan);
		Idx ++;
	}
}
for (var j = 0; j < WanPPPPortMapping.length-1; j++,i++)
{
	if(WanPPPPortMapping[j].InClient=="")
	{
		continue;
	}
	if(false == FindWanInfoByPortMapping(WanPPPPortMapping[j]))
	{
		continue;
	}
    var tmpWan = FindWanInfoByPortMapping(WanPPPPortMapping[j]);   

    if (tmpWan.ServiceList != 'TR069'
		&& tmpWan.ServiceList != 'VOIP'
		&& tmpWan.ServiceList != 'TR069_VOIP'
		&& tmpWan.Mode == 'IP_Routed')
	{
		PortMapping[Idx] = WanPPPPortMapping[j];
		PortMapping[Idx].Interface = MakeWanName(tmpWan);
		Idx ++;   
	}
}

	
function setPortMapEnable(id ,enabled)
{
	if(1 == enabled)
	{
		getElById(id).style.background = "url(../../../images/cus_images/btn_on.png) no-repeat";
	}
	else
	{
		getElById(id).style.background = "url(../../../images/cus_images/btn_off.png) no-repeat";
	}
}

function EnablePortMapping(id)
{
    if (AllowEditFlag == false)
	{
        return;
	}
	
	var instId = id.split('_')[1];
	enblPortList[instId] = 1 - enblPortList[instId];
	setPortMapEnable(id, enblPortList[instId]);
}

function DeletePortMapping(id)
{
	var instId = id.split('_')[1];
	var SubmitForm = new webSubmitForm();
	SubmitForm.addParameter(PortMapping[instId].domain,'');
	SubmitForm.setAction('del.cgi?RequestFile=' + fileUrl);
	SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
	SubmitForm.submit();
}

function DeletePortMappingList()
{
	if(PortMapping.length == 0)return;
	
	var SubmitForm = new webSubmitForm();
	for(var i = 0; i < PortMapping.length; i++)
	{
		SubmitForm.addParameter(PortMapping[i].domain,'');
	}
	
	SubmitForm.setAction('del.cgi?RequestFile=' + fileUrl);
	SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
	SubmitForm.submit();
}

function stPortMappingInst(domain, stDescription, stProtocol, stExternalPort, stInternalPort, stInClient, stEnabled)
{
	var portList;
	this.domain = domain;
	this.instId = domain.split('.')[8];
	this.stDescription = stDescription;
	this.stProtocol = stProtocol;
	this.stExternalPort = stExternalPort; 
	this.stInternalPort = stInternalPort; 
	this.stInClient = stInClient;
	this.stEnabled = stEnabled;
	
	portList = FormatPortStr(stInternalPort).split(':');
    this.innerPortStart = portList[0];
    this.innerPortEnd = portList[0];
    if(portList.length > 1){
        this.innerPortEnd = portList[1];
    }
	
	portList = FormatPortStr(stExternalPort).split(':');
    this.exterPortStart = portList[0];
    this.exterPortEnd = portList[0];
    if(portList.length > 1){
        this.exterPortEnd = portList[1];
    }
	
	this.modifyFlag = false;
	this.modifyPortFlag = false;
}


function setAllDisableTDE(flag)
{
    for(var i = 0; i < PortMapping.length; i++)
    {
       setDisable('portMappingInst_'+ i + "_1" ,flag);
       setDisable('portMappingInst_'+ i + "_2" ,flag);
       setDisable('portMappingInst_'+ i + "_3" ,flag);
       setDisable('portMappingInst_'+ i + "_4" ,flag);
       setDisable('portMappingInst_'+ i + "_5" ,flag);
    }
}
function PortMappingInstList(record)
{
	var instNum = record.length;
	
	this.showPortmappingList = function()
	{
		var htmlLines = '';
		var tdClass = "<td class=\"table_title align_center\"";
		
		if (instNum == 0 )
		{
			htmlLines += '<tr id="portMappingInst_record_no"' + ' class="tabal_center01" >';
			htmlLines += '<td >--</td>';
			htmlLines += '<td >--</td>';
			htmlLines += '<td >--</td>';
			htmlLines += '<td >--</td>';
			htmlLines += '<td >--</td>';
			htmlLines += '<td >--</td>';
			htmlLines += '</tr>';
		}
		else
		{ 
			for(var i = 0; i < instNum; i++)
			{
				htmlLines += "<tr id=\"portMappingInst_record_" + i + "\" >";
				htmlLines += tdClass + ">" + "<input type=\"text\" id=\"portMappingInst_" + i + "_1\" " + " size=\"5\" maxlength=\"256\" style=\"width: 135px\">" +  "</td>";
				
			    htmlLines += tdClass + ">" + "<select id=\"portMappingInst_" + i + "_2\" " + " size=\"1\">"
			    htmlLines += "<option value=\"TCP\" selected>TCP</option>" + "<option value=\"UDP\">UDP</option>" + "</select></td>";

				htmlLines += tdClass + ">" + "<input type=\"text\" id=\"portMappingInst_" + i + "_3\" " + " size=\"5\" maxlength=\"11\" style=\"width: 130px\">" +  "</td>";

				htmlLines += tdClass + ">" + "<input type=\"text\" id=\"portMappingInst_" + i + "_4\" " + " size=\"5\" maxlength=\"11\" style=\"width: 130px\">" +  "</td>";
				
				htmlLines += tdClass + ">" + "<input type=\"text\" id=\"portMappingInst_" + i + "_5\" " + " size=\"5\" maxlength=\"16\" style=\"width: 130px\">" +  "</td>";
				
				htmlLines += "<td>" + "<div id=\"portMappingInst_" + i + "_6\" " + " class=\"tb_switch\" onclick=\"EnablePortMapping(this.id);\">" + "</div>" + "</td>";
				
				htmlLines += "<td>" + "<div id=\"portMappingInst_" + i + "_7\" " + " class=\"tb_delete\" onclick=\"DeletePortMapping(this.id);\">" + "</div>" + "</td>" + "</tr>";
			}
		}
		
		return htmlLines;
	}
	
	this.showTblListDelIco = function()
	{
		for(var inst = 0; inst < record.length; inst++)
		{
			var icoId = "portMappingInst_" + inst + "_7";
			$("#" + icoId).css({
				"display" : "block"
			});
		}
	}

	this.fillUpListTblInst = function()
	{
		var InternalPortEnd;
		for(var inst = 0; inst < instNum; inst++)
		{
			setText("portMappingInst_" + inst + "_1", record[inst].Description);
			setSelect("portMappingInst_" + inst + "_2", (record[inst].Protocol).toUpperCase());
			if ('0' == record[inst].ExternalPortEndRange)
			{
				record[inst].ExternalPortEndRange = record[inst].ExternalPort;
				InternalPortEnd = record[inst].InternalPort;
			}
			else
			{
				InternalPortEnd = parseInt(record[inst].InternalPort,10) 
			          + (parseInt(record[inst].ExternalPortEndRange,10) - parseInt(record[inst].ExternalPort,10));
			}
			setText("portMappingInst_" + inst + "_3", record[inst].ExternalPort + ':' + record[inst].ExternalPortEndRange);			
			setText("portMappingInst_" + inst + "_4", record[inst].InternalPort + ':' + InternalPortEnd);
			setText("portMappingInst_" + inst + "_5", record[inst].InClient);
			enblPortList.push(record[inst].ProtMapEnabled);
			setPortMapEnable("portMappingInst_" + inst + "_6" ,enblPortList[inst]);
		}
	}
	
	this.getCurListInst = function(instId)
	{
		var curRowData = new stPortMappingInst(record[instId].domain,
											getValue("portMappingInst_" + instId + "_1"),
											getValue("portMappingInst_" + instId + "_2"),
											getValue("portMappingInst_" + instId + "_3"),
											getValue("portMappingInst_" + instId + "_4"),
											getValue("portMappingInst_" + instId + "_5"), enblPortList[instId]);
											
		return curRowData;
	}
	
	this.getAllListInst = function()
	{
		var curDataList = new Array();
		for(var inst = 0; inst < instNum; inst++)
		{
			curDataList.push(this.getCurListInst(inst));
		}
		
		return curDataList;
	}
	
}

function GetCurrentPortMapList()
{
    var curPortMappingList = new PortMappingInstList(PortMapping);
	return curPortMappingList;
}

function GetNewPortMappingInst()
{
	var newData = new stPortMappingInst("",getValue("PortMappingDescription"),getValue("PortMappingProtocolId"),getValue("ExternalPortId"),getValue("InnerPortId"),getValue("InternalClient"), "1");
											
	return newData;
}

function GetInterfacePath()
{
	var pathInst = 0xFF;
	for(var k = 0; k < WanInfo.length; k++ )
	{
		if(WanInfo[k].ServiceList != 'TR069'
		&& WanInfo[k].ServiceList != 'VOIP'
        && WanInfo[k].ServiceList != 'TR069_VOIP'
		&& WanInfo[k].ServiceList.indexOf('INTERNET') != -1
        && WanInfo[k].Mode == 'IP_Routed')
		{
			pathInst = k;
			break;
		}
	}
	return parseInt(pathInst);
}

function portListInstIpChk(innerHostIp)
{
    if (innerHostIp == "")
    {
        AlertEx(portmapping_language['bbsp_hostipisreq']);
        return false;
    } 
	
    if (isAbcIpAddress(innerHostIp) == false)
    {
        AlertEx(portmapping_language['bbsp_hostipinvalid']);
        return false;
    }

	var ip4 = innerHostIp.split(".");
    if ( parseInt(ip4[3],10) == 0 )
    {
		AlertEx(portmapping_language['bbsp_hostipoutran']);
		return false;
    }
	
	return true;
}

function portValueValidChk(innerPortRange, externalPortRange)
{
	var externalPort = $.trim(externalPortRange);
    var portList = FormatPortStr(externalPort).split(':');
    var externalStartPort = portList[0];
    var externalEndPort = portList[0];
    if(portList.length > 1)
	{
        externalEndPort = portList[1];
    }

    if (parseInt(externalEndPort,10) < parseInt(externalStartPort,10))
    {
	    AlertEx(portmapping_language['bbsp_extstartportleqendport'] + "(" + externalStartPort + ")");
	    return false;     	
    }

	if ((7070 <= parseInt(externalStartPort,10)) && (7079 >= parseInt(externalStartPort,10)) || (7070 <= parseInt(externalEndPort,10)) && (7079 >= parseInt(externalEndPort,10)))
	{
		if ( ConfirmEx(portmapping_language['bbsp_confirm1']) == false )
		{
			return false;
		}
	}

	return true;
}

function PortListCheck(wanIdx)
{   
	var _new = GetNewPortMappingInst();
    var dev = domainTowanname(WanInfo[wanIdx].domain);

	var newport = PS_GetCmdFormat("pm", dev, _new.stProtocol, _new.exterPortStart, _new.exterPortEnd);

	if(true == PS_CheckReservePort("add", newport, newport))
	{            
		AlertEx(portmapping_language['bbsp_conflictport']);
		return true;
	}

    return false;
}

function PortListCheck_ex(instRec)
{   
	var _new = instRec;
	var index = _new.instId - 1;
	var _old = oldPmList[index];
    var dev = domainTowanname(GetWanDomain(instRec.domain));

	var newport = PS_GetCmdFormat("pm", dev, _new.stProtocol, _new.exterPortStart, _new.exterPortEnd);
	var oldport = PS_GetCmdFormat("pm", dev, _old.stProtocol, _old.exterPortStart, _old.exterPortEnd);
	if(true == PS_CheckReservePort("set", newport, oldport))
	{            
		AlertEx(portmapping_language['bbsp_conflictport']);
		return true;
	}
	
    return false;

}

function CheckForm(type)
{
    switch (type)
    {
       case 3:
          return CheckPortMappingCfg();
          break;
    }
	return true;
}

function CheckPortMappingCfg()
{
	var wanIdx = 0;
	wanIdx = GetInterfacePath();
	var MAX_INST_NUM = (getValue('PortMappingProtocolId') == "TCP/UDP") ? '31' : '32';
	
	if(PortMapping.length >= parseInt(MAX_INST_NUM))
	{
		AlertEx(portmapping_language['bbsp_mappingfull']);
		return false;
	}
	
	if (wanIdx == INVALID_WAN_ID)
	{
		 AlertEx(portmapping_language['bbsp_wanconinvalid']);
		 return false;
	}

	if ( WanInfo[wanIdx].IPv4NATEnable < 1 )
	{
		 AlertEx(MakeWanName1(WanInfo[wanIdx]) + portmapping_language['bbsp_notnat']);
		 return false;
	}


	if (true != portListInstIpChk($.trim(getValue("InternalClient"))))
	{
	    return false;
	}
	
	if (true != portValueValidChk(getValue("InnerPortId"), getValue("ExternalPortId")))
	{
	    return false;
	}
	
	return true;
}

function GetModifiedPmList()
{
	var modifyPmList = GetCurrentPortMapList().getAllListInst();
	
	for(var i = 0; i < modifyPmList.length; i++)
	{
		if(modifyPmList[i].stProtocol != oldPmList[i].stProtocol)
		{
			modifyPmList[i].modifyFlag = true;
			modifyPmList[i].modifyPortFlag = true;
			continue;
		}
		if(modifyPmList[i].stExternalPort != oldPmList[i].stExternalPort)
		{
			modifyPmList[i].modifyFlag = true;
			modifyPmList[i].modifyPortFlag = true;
			continue;
		}
		if(modifyPmList[i].stInternalPort != oldPmList[i].stInternalPort)
		{
			modifyPmList[i].modifyFlag = true;
			modifyPmList[i].modifyPortFlag = true;
			continue;
		}
		
		if(modifyPmList[i].stDescription != oldPmList[i].stDescription)
		{
			modifyPmList[i].modifyFlag = true;
			continue;
		}
		if(modifyPmList[i].stInClient != oldPmList[i].stInClient)
		{
			modifyPmList[i].modifyFlag = true;
			continue;
		}
		if(modifyPmList[i].stEnabled != oldPmList[i].stEnabled)
		{
			modifyPmList[i].modifyFlag = true;
			continue;
		}
	}

	return modifyPmList;
}

function GetChangedPmList()
{
	var newPmList = new Array();
	var tmpPmList = GetModifiedPmList();

	for(var i = 0; i < tmpPmList.length; i++)
	{
		if(tmpPmList[i].modifyFlag == true)
		{
			newPmList.push(tmpPmList[i]);
		}
	}

	if(newPmList.length == 0)
	{
		newPmList.push(tmpPmList[0]);
	}

	return newPmList;
}


function GetWanDomain(_domain)
{
	var curWanDomain = "";
	var WanDomainArr = new Array();
	var tmpArr = _domain.split('.');
	for(var i = 0; i < 7; i++)
	{
		WanDomainArr.push(tmpArr[i]);
	}
	curWanDomain = WanDomainArr.join(".");
	return curWanDomain;
}

function CheckPortMappingModify(instList)
{
	for(var i = 0; i < instList.length; i++)
	{	
		if (true != portListInstIpChk(instList[i].stInClient))
		{
			return false;
		}
		if (true != portValueValidChk(instList[i].stInternalPort, instList[i].stExternalPort))
		{
			return false;
		}
	}
	
	return true;
}

function GetRowIndexByDomain(_domain)
{
	var rowIndex = 0;
	for(var i = 0; i < PortMapping.length; i++)
	{
		if(_domain == PortMapping[i].domain)
		{
			rowIndex = i;
		}
	}
	
	return rowIndex;
}

function ModifyPortMappingList()
{
	var prefixList = new Array('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z');
	var needModifyList = GetChangedPmList();
	
	if(true != CheckPortMappingModify(needModifyList))
	{
		return false;
	}
	
	setDisable('btnModify',1);
	setDisable('btnDelete',1);
	
	var instPrefix;
	var portPrefix;
	var SubmitForm = new webSubmitForm();
	var url = 'complex.cgi?';
	for(var i = 0; i < needModifyList.length; i++)
	{
		instPrefix = prefixList[i];
		var urlPrefix = (i == 0) ? instPrefix : ('&' + instPrefix);
		var index = GetRowIndexByDomain(needModifyList[i].domain);
		
		SubmitForm.addParameter(instPrefix +'.PortMappingEnabled', enblPortList[index]);
		SubmitForm.addParameter(instPrefix +'.PortMappingDescription',getValue("portMappingInst_" + index + "_1"));
		SubmitForm.addParameter(instPrefix +'.InternalClient',getValue("portMappingInst_" + index + "_5"));
		SubmitForm.addParameter(instPrefix +'.PortMappingProtocol',getValue("portMappingInst_" + index + "_2"));
		SubmitForm.addParameter(instPrefix +'.ExternalPort',ParsePortStart(getValue("portMappingInst_" + index + "_3")));
		SubmitForm.addParameter(instPrefix +'.ExternalPortEndRange',ParsePortEnd(getValue("portMappingInst_" + index + "_3")));
		SubmitForm.addParameter(instPrefix +'.InternalPort',ParsePortStart(getValue("portMappingInst_" + index + "_4")));

		url += urlPrefix + '='+ needModifyList[i].domain;
	}
	
	url +=  '&RequestFile=' + fileUrl;
	
	SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
	SubmitForm.setAction(url);
	SubmitForm.submit();
	
}

function AddFirstParam(Interface, stDescription, stInterClient, stInterPort, stExterPort, stExterPortEnd)
{
	var Onttoken = getValue('onttoken');
	$.ajax({
	type : "POST",
	async : false,
	cache : false,
	data : 'x.PortMappingEnabled=1' +'&x.PortMappingDescription='+ encodeURIComponent(stDescription)  + '&x.InternalClient=' + stInterClient 
	      + '&x.PortMappingProtocol=TCP' + '&x.InternalPort=' + stInterPort + '&x.ExternalPort=' + stExterPort 
		  + '&x.ExternalPortEndRange=' + stExterPortEnd +'&x.X_HW_Token=' + Onttoken,
	url :  'addcfg.cgi?x=' + Interface + '.PortMapping' 
		   + '&RequestFile=html/ipv6/not_find_file.asp',
	error:function(XMLHttpRequest, textStatus, errorThrown) 
	{
		if(XMLHttpRequest.status == 404)
		{
		}
	}
	});
}

function AddSubmitParam(SubmitForm,type)
{
	setDisable('btnApply_ex',1);
	
	var Interface = WanInfo[GetInterfacePath()].domain;
	var url;
	
	var stProtocol = getValue('PortMappingProtocolId');
	var stDescription = getValue('PortMappingDescription');
	var stInterClient = getValue('InternalClient');
	var stInterPort = ParsePortStart(getValue('InnerPortId'));
	var stExterPort = ParsePortStart(getValue('ExternalPortId'));
	var stExterPortEnd = ParsePortEnd(getValue('ExternalPortId'));
	switch(stProtocol)
	{
		case "TCP":
		case "UDP":
			break;
		case "TCP/UDP":
			stProtocol = "UDP";
			AddFirstParam(Interface, stDescription, stInterClient, stInterPort, stExterPort, stExterPortEnd);
		default:
			break;
	}
	
    SubmitForm.addParameter('x.PortMappingEnabled', '1');
    SubmitForm.addParameter('x.PortMappingDescription', stDescription);
	SubmitForm.addParameter('x.InternalClient', stInterClient);
	SubmitForm.addParameter('x.PortMappingProtocol',stProtocol);
	SubmitForm.addParameter('x.InternalPort', stInterPort);
	SubmitForm.addParameter('x.ExternalPort', stExterPort);
	SubmitForm.addParameter('x.ExternalPortEndRange', stExterPortEnd);

	url = "addcfg.cgi?x=" + Interface + ".PortMapping" + '&RequestFile=' + fileUrl;
	
	SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
	SubmitForm.setAction(url);
    	
}

function JumpToModify()
{
	if(PortMapping.length == 0)return;
	AllowEditFlag = true;
	setDisplay('btnEditRow', 0);
	setDisplay('btnModifyRow', 1);
    setAllDisableTDE(0);
	GetCurrentPortMapList().showTblListDelIco();
	
}

function LoadFrame()
{
	loadlanguage();
	
	GetCurrentPortMapList().fillUpListTblInst();
	
	oldPmList = GetCurrentPortMapList().getAllListInst();
	
	if(PortMapping.length == 0)
	{
		setDisplay('btnEditRow', 0);
	}
	else
	{
		setDisplay('btnEditRow', 1);
	}
	
	if(isValidIpAddress(numpara) == true)
	{
		setText('InternalClient', numpara);
	}
    setAllDisableTDE(1);
    AllowEditFlag = false;
	
}

</script>
<style type="text/css">
	.TextBox
	{
		width:180px;  
	}
	.Select
	{
		width:183px;  
	}
	.SelectCfg
	{
		width:183px; 
	}
	.tb_switch
	{
		height: 20px;
		width: 55px;
		background: url(../../../images/cus_images/btn_on.png) no-repeat;
	}
	.tb_delete
	{
		height: 20px;
		width: 25px;
		background: url(../../../images/cus_images/del.png) no-repeat;
		display : none;
	}
</style>
</head>
<body onLoad="LoadFrame();" class="iframebody" >
<div class="title_spread"></div>
<div id="FuctionPageArea" class="FuctionPageAreaCss">
<div id="FunctionPageTitle" class="FunctionPageTitleCss">
<span id="PageTitleText" class="PageTitleTextCss" BindText="bbsp_mune1"></span>
</div>
<div id="PmContentitle" class="FuctionPageContentCss">
<div id="PageSumaryInfo1" class="PageSumaryInfoCss" BindText="bbsp_portmapping_title_tde"></div>
</div>
<form id="ConfigForm">
<table border="0" cellpadding="0" cellspacing="1"  width="100%">
<li   id="PortMappingDescription"    RealType="TextBox"            DescRef="bbsp_mappingtde"           RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"             InitValue="Empty"/>
<li   id="InternalClient"  			RealType="TextBox"  DescRef="bbsp_inthosttde"         RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   MaxLength="32"  InitValue="Empty"/>                                                                  
<li   id="PortMappingProtocolId"    RealType="DropDownList"       DescRef="bbsp_protocolmh"      RemarkRef="Empty"       ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"  Elementclass="SelectCfg"   InitValue="[{TextRef:'TCP',Value:'TCP'},{TextRef:'UDP',Value:'UDP'},{TextRef:'TCPUDP',Value:'TCP/UDP'}]"/>
<li   id="ExternalPortId"    RealType="TextBox"            DescRef="bbsp_extportmh"           RemarkRef="bbsp_exportrange"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"             InitValue="Empty"/>
<li   id="InnerPortId"    RealType="TextBox"            DescRef="bbsp_intportmh"           RemarkRef="bbsp_inportrange"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"             InitValue="Empty"/>
</table>
<script>
var TableClass = new stTableClass("PageSumaryTitleCss table_title width_per40", "table_right", "");
PortMappingCfgFormList = HWGetLiIdListByForm("ConfigForm", null);
HWParsePageControlByID("ConfigForm", TableClass, portmapping_language, null);
</script>
<table width="100%" border="0" cellspacing="0" cellpadding="0" > 
  <tr> 
	<td class="table_submit"> 
		<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
		<button name="btnApply_ex" id="btnApply_ex" type="button" class="BluebuttonGreenBgcss buttonwidth_100px" onClick="Submit(3);"><script>document.write(portmapping_language['bbsp_add']);</script></button>
  </tr> 
</table> 
</form>

<div style="height:20px;"></div>
<table class="tabal_noborder_bg" id="portMappingInst" width="100%" cellpadding="0" cellspacing="1" style="padding-left:10px;padding-right:10px;"> 
<tr class="head_title_tde"> 
  <td width="20%" BindText='bbsp_mappingtde1'></td> 
  <td width="10%" BindText='bbsp_protocol'></td> 
  <td width="20%" BindText='bbsp_extporttde'></td> 
  <td width="20%" BindText='bbsp_intporttde'></td> 
  <td width="20%" BindText='bbsp_inthosttde1'></td> 
  <td width="10%" colspan="2" BindText='bbsp_enabletde'></td> 
</tr> 
<script language="JavaScript" type="text/javascript">
document.write(GetCurrentPortMapList().showPortmappingList());
</script> 
</table> 

<table width="100%" border="0" cellspacing="0" cellpadding="0" > 
  <tr id="btnEditRow"> 
	<td class="title_bright1"> 
	<a id="btnEdit" href="#" onClick="JumpToModify();" style="font-size:14px;color:#266B94;text-decoration:none;white-space:nowrap;padding-right:180px;"><script>document.write(portmapping_language['bbsp_edit']);</script></a></td> 
  </tr> 
  <tr id="btnModifyRow" style="display:none"> 
	<td class="title_bright1">
	<a id="btnModify" href="#" onClick="ModifyPortMappingList();" style="font-size:14px;color:#266B94;text-decoration:none;white-space:nowrap;margin-left:10px;margin-right:10px"><script>document.write(portmapping_language['bbsp_ok']);</script></a>
	<a id="btnEmpty" style="margin-left:10px;margin-right:10px"></a>
	<a id="btnDelete" href="#" onClick="DeletePortMappingList();" style="font-size:14px;color:#266B94;text-decoration:none;white-space:nowrap;margin-left:5px;margin-right:5px"><script>document.write(portmapping_language['bbsp_del_all']);</script></a>
	</td> 
  </tr> 
</table> 
<div style="height:20px;"></div>
</div>
<div style="height:20px;"></div>
<script>
ParseBindTextByTagName(portmapping_language, "span",  1);
ParseBindTextByTagName(portmapping_language, "div",  1);
</script>
</body>
</html>
