<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>

<title>IP Incoming Filter</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="javascript" src="../common/<%HW_WEB_CleanCache_Resource(page.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/lanuserinfo.asp"></script>
<script language="javascript" src="../common/wan_check.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="javascript" src="../common/wan_control.asp"></script>
<style>
.SelectDdns{
	width: 103px;
}
.InputRuleName{
	width: 98px;
}
.InputDdns{
	width: 120px;
}
</style>
<script language="JavaScript" type="text/javascript">


function getWanOffirewall(val)
{
   for (var i = 0; i < WanInfo.length; i++)
   {
      if (WanInfo[i].domain == val)
	  {
	      return WanInfo[i];
	  }
   }
   return "&nbsp;";
}

function filtergetmaskLength(Mask)
{
	var ulTmp;
	var ulCount = 0;
	var ulmask;
	ulmask = SubnetAddress2DecNum(Mask);
	
	if(Mask == '')
		return '';
	
	if (ulTmp)
	{
		return 0;
	}

	while (ulmask != 0)
	{
		ulmask = ulmask << 1;
		ulCount++;
	}
	return ulCount;
}

function filtergetmaskLength6(Mask)
{
	if(Mask == '' || Mask == undefined)
	{
		return '';
	}
	
	var mask = ['0','8000','C000','E000','F000','F800','FC00','FE00','FF00','FF80','FFC0','FFE0','FFF0','FFF8','FFFC','FFFE','FFFF'];
	var addrParts = Mask.split(':');
	var num = 0;
	var masknum = 0;		
	
	for (i = 0; i < 8; i++)
	{
		for(masknum = 0;masknum < 16;masknum++)
		{
			if(addrParts[i] == mask[masknum])
			{
				break;
			}
		}
		num += masknum;
	}

	return num;
}

function filtergetmask(length)
{
	var bitlength = length % 8;
	var mask = ['0','128','192','224','240','248','252','254'];
	var maskout;

	if(length == '' || length == undefined)
	{
		return '';
	}
	
	if((length < 8)&&(length >= 1))
	{
		maskout = mask[bitlength] + '.' + '0' + '.' + '0' + '.' + '0';
	}

	if((length < 16)&&(length >= 8))
	{
		maskout = '255' + '.' + mask[bitlength] + '.' + '0' + '.' + '0';
	}

	if((length < 24)&&(length >= 16))
	{
		maskout = '255' + '.' + '255' + '.' + mask[bitlength] + '.' + '0';
	}

	if((length < 32)&&(length >= 24))
	{
		maskout = '255' + '.' +  '255' + '.' + '255' + '.' + mask[bitlength];
	}

	if(length == 32)
	{
		maskout = '255' + '.' +  '255' + '.' + '255' + '.' + '255';
	}

	return maskout;
}

function filtergetmask6(length)
{
	var bitlength = length % 16;
	var mask = ['0','8000','C000','E000','F000','F800','FC00','FE00','FF00','FF80','FFC0','FFE0','FFF0','FFF8','FFFC','FFFE','FFFF'];
	var maskout;
	if(length == '' || length == undefined)
	{
		return '';
	}
	if((length < 16)&&(length >= 1))
	{
		maskout = mask[bitlength] + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0';
	}

	if((length < 32)&&(length >= 16))
	{
		maskout = 'FFFF' + ':' + mask[bitlength] + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0';
	}

	if((length < 48)&&(length >= 32))
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + mask[bitlength] + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0';
	}

	if((length < 64)&&(length >= 48))
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + mask[bitlength] + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0';
	}

	if((length < 80)&&(length >= 64))
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + mask[bitlength] + ':' + '0' + ':' + '0' + ':' + '0';
	}

	if((length < 96)&&(length >= 80))
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + mask[bitlength] + ':' + '0' + ':' + '0';
	}

	if((length < 112)&&(length >= 96))
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' +  'FFFF' + ':' + mask[bitlength] + ':' + '0';
	}

	if((length < 128)&&(length >= 112))
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' +  'FFFF' + ':' + 'FFFF' + ':' + mask[bitlength];
	}

	if(length == 128)
	{
		maskout = 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' + 'FFFF' + ':' +  'FFFF' + ':' + 'FFFF' + ':' + 'FFFF';
	}

	if(length == 0)
	{
		maskout = '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0' + ':' + '0';
	}
	return maskout;
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
		setObjNoEncodeInnerHtmlValue(b, ipincoming_language[b.getAttribute("BindText")]);
	}
}

var selctIndex = -1;

function stFilterIn(Domain, Name, Interface, Type, IPVersion, RuleNumberOfEntries)
{
    this.Domain = Domain;
	this.Name = Name;
    this.Interface = Interface;
	while ((this.Interface != null) && (this.Interface.substr(this.Interface.length-1,this.Interface.length)=="."))
	{
		this.Interface = this.Interface.substr(0,this.Interface.length-1);
	}
    this.Type = Type;
    this.IPVersion = IPVersion;
	this.RuleNumberOfEntries = RuleNumberOfEntries;
}

function stFilterInRule(Domain, Protocol, Action, RejectType, IcmpType, X_HW_PrivateFlag, Enabled)
{
    this.Domain = Domain;
	this.Protocol = Protocol;
    this.Action = Action;
    this.RejectType = RejectType;
    this.IcmpType = IcmpType;
	this.X_HW_PrivateFlag = X_HW_PrivateFlag;
	this.Enabled = Enabled;
}

function stFilterInRuleOrgin(Domain, IPAddress, Mask, StartPort, EndPort)
{
    this.Domain = Domain;
	this.IPAddress = IPAddress;
    this.Mask = Mask;
    this.StartPort = StartPort;
    this.EndPort = EndPort;
}

function stFilterInRuleDes(Domain, IPAddress, Mask, StartPort, EndPort)
{
    this.Domain = Domain;
	this.IPAddress = IPAddress;
    this.Mask = Mask;
    this.StartPort = StartPort;
    this.EndPort = EndPort;
}

function findFilterInIndex(Domain)
{
	var domain_rule = Domain.split(".");
	var i;
	for (i = 0;i < FilterIn.length - 1;i++)
	{
		var domain_wall = FilterIn[i].Domain.split(".");
		if(domain_rule[3] == domain_wall[3])
		{
			return i;
		}
	}
}


var FilterIn = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_TDE_Firewall.Firewall.{i}, Name|Interface|Type|IPVersion|RuleNumberOfEntries, stFilterIn);%>;
var FilterInRule = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_TDE_Firewall.Firewall.{i}.Rule.{i}, Protocol|Action|RejectType|IcmpType|X_HW_PrivateFlag|Enabled, stFilterInRule);%>;
var FilterInOrgin = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_TDE_Firewall.Firewall.{i}.Rule.{i}, X_HW_OrgIPAddress|X_HW_OrgMask|X_HW_OrgStartPort|X_HW_OrgEndPort, stFilterInRuleOrgin);%>;
var FilterInDes = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_TDE_Firewall.Firewall.{i}.Rule.{i}, X_HW_DstIPAddress|X_HW_DstMask|X_HW_DstStartPort|X_HW_DstEndPort, stFilterInRuleDes);%>;
var FilterNum = FilterInRule.length - 1;


var TempIPv6Prefix = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.X_HW_IPv6Interface.1.IPv6Prefix.1.Prefix);%>';
var Br0IPv6Prefix = TempIPv6Prefix.split('/')[0];
var Prelength = TempIPv6Prefix.split('/')[1];

function PutPrefix(Br0IPv6Prefixtmp, Prelengthtmp)
{
	var Br0IPv6PrefixList = standIpv6Address(Br0IPv6Prefixtmp);
	var Masklist = filtergetmask6(Prelengthtmp).split(':');
	
	var TempIPv6PrefixNew = '';

	for(var fixlength = 0;fixlength < 4;fixlength++)
	{
		var tmp;
		tmp = parseInt(Br0IPv6PrefixList[fixlength], 16) & parseInt(Masklist[fixlength], 16);
		Br0IPv6PrefixList[fixlength] = tmp.toString(16);

		TempIPv6PrefixNew += "0000".substring(0, 4 - Br0IPv6PrefixList[fixlength].length) + Br0IPv6PrefixList[fixlength];

		TempIPv6PrefixNew += ':';
	}

	return TempIPv6PrefixNew + ":";
}

Br0IPv6Prefix = PutPrefix(Br0IPv6Prefix, Prelength);

function filterWan(WanItem)
{	
	return true;
}
var WanInfo = GetWanListByFilter(filterWan);
function WriteOption(mode)
{
	var List = getElementById("Interface");
	List.options.length = 0;
	
	var i;
	if(mode == 1)
	{
		List.options.add(new Option('',''));
	}
	for (i = 0; i < WanInfo.length; i++)
    {
    	if(WanInfo[i].Mode == "IP_Routed")
		{
			List.options.add(new Option(MakeWanName1(WanInfo[i]),WanInfo[i].domain));
		}
    }
	List.options.add(new Option(ipincoming_language['LAN'],"LAN"));
	List.options.add(new Option(ipincoming_language['WAN'],"WAN"));
}
function getWanOfDynamicRoute(val)
{
   for (var i = 0; i < WanInfo.length; i++)
   {
      if (WanInfo[i].domain == val)
	  {
	      return WanInfo[i];
	  }
   }
   return "&nbsp;";
}
function clickRemove() 
{
    if ((FilterIn.length-1) == 0)
	{
	    AlertEx(ipincoming_language['bbsp_norule']);
	    return;
	}

	if (selctIndex == -1)
	{
	    AlertEx(ipincoming_language['bbsp_cannotdel']);
	    return;
	}
    var rml = getElement('rml');
    var noChooseFlag = true;
    if ( rml.length > 0)
    {
         for (var i = 0; i < rml.length; i++)
         {
             if (rml[i].checked == true)
             {   
                 noChooseFlag = false;
             }
         }
    }
    else if (rml.checked == true)
    {
        noChooseFlag = false;
    }
    if ( noChooseFlag )
    {
        AlertEx(ipincoming_language['bbsp_plschoose']);
        return ;
    }
 
	if (ConfirmEx(ipincoming_language['bbsp_isdel']) == false)
	{
		document.getElementById("DeleteButton").disabled = false;
		return;
    }

    setDisable('btnApply_ex',1);
    setDisable('cancelButton',1);
	
	var rml = getElement('rml');
	if (rml == null)
		return;

	var SubmitForm = new webSubmitForm();
	var cnt = 0;
	with (document.forms[0])
	{
		if (rml.length > 0)
		{
			var filtercnt = new Array(FilterIn.length - 1);
			var j = 0;
			for(j = 0;j < FilterIn.length - 1;j++)
			{
				filtercnt[j] = 0;
			}
			for (var i = 0; i < rml.length; i++)
			{
				if (rml[i].checked == true)
				{
					var filterdomainid;
					filterdomainid = findFilterInIndex(rml[i].value);
					filtercnt[filterdomainid]++;
					SubmitForm.addParameter(rml[i].value,'');
					if(FilterIn[filterdomainid].RuleNumberOfEntries == filtercnt[filterdomainid])
					{
						SubmitForm.addParameter(FilterIn[filterdomainid].Domain,'');
					}
					cnt++;
				}
			}
		}
		else if (rml.checked == true)
		{
			var filterdomainid;
			filterdomainid = findFilterInIndex(rml.value);
			if(FilterIn[filterdomainid].RuleNumberOfEntries == 1)
			{
				SubmitForm.addParameter(FilterIn[filterdomainid].Domain,'');
			}
			else
			{
				SubmitForm.addParameter(rml.value,'');
			}			
			cnt++;
		}
	}

	SubmitForm.setAction('del.cgi?RequestFile=' + 'html/bbsp/ipincoming/ipincomingtde.asp');
	SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
	SubmitForm.submit();;
}


function LoadFrame()
{   
    if (FilterNum == 0)
    {   
        selectLine('record_no');      
    }
    else
    {
        selectLine('record_0');
    }
	setDisplay('ConfigForm',0);    
	InitControlDataType();
	loadlanguage();
}


function setCtlDisplay(record, rule, orgin, des)
{	
    setText('RuleNameId',record.Name);
	setSelect('Interface',record.Interface);
	setSelect('Direction',record.Type);
	setSelect('IPVersion',record.IPVersion);
	if (rule.Protocol != '')
	{
		setSelect('Protocol',(rule.Protocol).toUpperCase());
	}
	else
	{
		setSelect('Protocol','ALL');
	}
	setSelect('Action',rule.Action);
	setCheck('Enabled',rule.Enabled);

	if(orgin.IPAddress != '')
	{
		if(record.IPVersion == '6')
		{
			var orginmask = (orgin.Mask !='') ? ('/' + filtergetmaskLength6(orgin.Mask)) : "" ;
						
		}
		else
		{
			var orginmask = (orgin.Mask !='') ? ('/' + filtergetmaskLength(orgin.Mask)) : "" ;
		}
		
		setText('Orgin', orgin.IPAddress + orginmask );
	}
	else
	{
		setText('Orgin', '');
	}
	if((orgin.StartPort == '0')&&(orgin.EndPort == '0'))
	{
		setText('OrgPortStart', '');
		setText('OrgPortEnd', '');
	}
	else
	{
		setText('OrgPortStart', orgin.StartPort);
		setText('OrgPortEnd', orgin.EndPort);
	}
	if(des.IPAddress != '')
	{
		if(record.IPVersion == '6')
		{
			var desmask = (des.Mask !='') ? ('/' + filtergetmaskLength6(des.Mask)) : "" ;
						
		}
		else
		{
			var desmask = (des.Mask !='') ? ('/' + filtergetmaskLength(des.Mask)) : "" ;

		}
		setText('Destination', des.IPAddress + desmask );
	}
	else
	{
		setText('Destination', '');		
	}
	if((des.StartPort == '0')&&(des.EndPort == '0'))
	{
		setText('DesPortStart', '');
		setText('DesPortEnd', '');
	}
	else
	{
		setText('DesPortStart', des.StartPort);
		setText('DesPortEnd', des.EndPort);
	}
	protocalChange();
	versionChange();

	setSelect('RejectType',rule.RejectType);
	setSelect('ICMPType',rule.IcmpType);
}

function setControl(index)
{
    var record;
	var rule;
	var orgin;
	var des;
    selctIndex = index;
	setDisable("Interface", 0);
	setDisable("Direction", 0);
	WriteOption(0);
    if (index == -1)
	{
		InitProtocolList(1);
	    if (FilterInRule.length >= 32+1)
        {
            setDisplay('ConfigForm', 0);
            AlertEx(ipincoming_language['bbsp_ipfilterfull']);
            return;
        }
        else
        {
			record = new stFilterIn('', '', 'LAN', 'In', '4');
			rule = new stFilterInRule('', 'TCP', 'Permit', '', '', '', '');
			orgin = new stFilterInRuleOrgin('', '', '', '', '');
			des = new stFilterInRuleDes('', '', '', '', '');

            setDisplay('ConfigForm', 1);
	        setCtlDisplay(record,rule,orgin,des);
        }
		setDisable("IPVersion", 0);
	}
    else if (index == -2)
    {
        setDisplay('ConfigForm', 0);
    }
	else
	{
		WriteOption(1);
		InitProtocolList(0);

		rule = FilterInRule[index];
		orgin = FilterInOrgin[index];
		des = FilterInDes[index];
		var filterdomainid;
		filterdomainid = findFilterInIndex(FilterInRule[index].Domain)
		record = FilterIn[filterdomainid];
		
        setDisplay('ConfigForm', 1);
	    setCtlDisplay(record,rule,orgin,des);

		setDisable("IPVersion", 1);
		setDisable("Interface", 1);
		setDisable("Direction", 1);
		
	}

    setDisable('btnApply_ex',0);
    setDisable('cancelButton',0);
}

function IpFilterPortInputChk(portInfo)
{
	if(portInfo == '')
	{
		return true;	
	}

	if(!isPlusInteger(portInfo))
	{
		AlertEx(ipincoming_language['port_port_invalid'] +"("+ portInfo+ ")");
		return false;
	}

	if((parseInt(portInfo,10) < 0)||(parseInt(portInfo,10) > 65535))
	{
		AlertEx(ipincoming_language['port_port_invalid'] +"("+ portInfo+ ")");
		return false;
	}

	return true;	
}
function IpFilterPortValidChk()
{
    var orgStartPort = getValue('OrgPortStart');
    var orgEndPort = getValue('OrgPortEnd');
    var desStartPort = getValue('DesPortStart');
    var desEndPort = getValue('DesPortEnd');

	if(true != IpFilterPortInputChk(orgStartPort))
    {
        return false;
    }
	if(true != IpFilterPortInputChk(orgEndPort))
    {
        return false;
    }
	if(true != IpFilterPortInputChk(desStartPort))
    {
        return false;
    }
	if(true != IpFilterPortInputChk(desEndPort))
    {
        return false;
    }
    
	if ((orgStartPort != "") && (orgEndPort != "")
		&& (parseInt(orgStartPort, 10) > parseInt(orgEndPort, 10)))
	{
		AlertEx(ipincoming_language['bbsp_startportleqendport']);
		return false;     	
	}

	if ((desStartPort != "") && (desEndPort != "")
		&& (parseInt(desStartPort, 10) > parseInt(desEndPort, 10)))
	{
		AlertEx(ipincoming_language['bbsp_startportleqendport']);
		return false;     	
	}
    return true;
}
function IpFilterRepeateCfgChk()
{
    var stProtocol = getValue('Protocol');
	var stInterface = getValue('Interface');
	var stType = getValue('Direction');
	var stAction = getValue('Action');
	var stVersion = getValue('IPVersion');

	var stOrgIpAdress = getValue('Orgin');
	var stOrgStartPort = getValue('OrgPortStart');
	var stOrgEndPort = getValue('OrgPortEnd');

	var stDesIpAdress = getValue('Destination');
	var stDesStartPort = getValue('DesPortStart');
	var stDesEndPort = getValue('DesPortEnd');

	var stIcmpType = getValue("ICMPType");
	var stRejectType = getValue("RejectType");

	var orglist = stOrgIpAdress.split("/");
	var deslist = stDesIpAdress.split("/");

	var orgip = '';
	var orgmask = '';
	var desip = '';
	var desmask = '';
	
	if(stOrgIpAdress != '')
	{
		orgip = orglist[0];
		if(stVersion == '4')
		{
			orgmask = filtergetmask(orglist[1]);
		}
		else
		{
			orgmask = filtergetmask6(orglist[1]);
		}
	}

	if(stDesIpAdress != '')
	{
		desip = deslist[0];
		if(stVersion == '4')
		{
			desmask = filtergetmask(deslist[1]);
		}
		else
		{
			desmask = filtergetmask6(deslist[1]);
		}
	}

	if(stProtocol != 'ICMP')
	{
		stIcmpType = '';
	}

	if(stAction != 'Reject')
	{
		stRejectType = '';
	}
	
	if(stOrgStartPort == '')
	{
		stOrgStartPort = 0;
	}
	if(stOrgEndPort == '')
	{
		stOrgEndPort = 0;
	}
	if(stDesStartPort == '')
	{
		stDesStartPort = 0;
	}
	if(stDesEndPort == '')
	{
		stDesEndPort = 0;
	}
	
	for (i = 0; i < FilterNum; i++)
	{	
		if(i != selctIndex)
		{	
			var filterdomainid;
			filterdomainid = findFilterInIndex(FilterInRule[i].Domain)
			
			if((FilterIn[filterdomainid].Interface == stInterface)
			 &&(FilterIn[filterdomainid].Type == stType)
			 &&(FilterIn[filterdomainid].IPVersion == stVersion)
			 &&((FilterInRule[i].Protocol == stProtocol)||((FilterInRule[i].Protocol == "TCP")&&(stProtocol == "TCP/UDP"))||((FilterInRule[i].Protocol == "UDP")&&(stProtocol == "TCP/UDP")))
			 &&(FilterInRule[i].Action == stAction)
			 &&(FilterInRule[i].RejectType == stRejectType)
			 &&(FilterInRule[i].IcmpType == stIcmpType)
			 &&(FilterInOrgin[i].IPAddress == orgip)
			 &&(FilterInOrgin[i].Mask == orgmask)
			 &&(FilterInOrgin[i].StartPort == stOrgStartPort)
			 &&(FilterInOrgin[i].EndPort == stOrgEndPort)
			 &&(FilterInDes[i].IPAddress == desip)
			 &&(FilterInDes[i].Mask == desmask)
			 &&(FilterInDes[i].StartPort == stDesStartPort)
			 &&(FilterInDes[i].EndPort == stDesEndPort))
			{
				AlertEx(ipincoming_language['bbsp_rulerepeat']);		    
				return false;
			}
		}
	} 
	return true;   
}
function IpFilterDescpChk()
{	
    return true;
}

function CheckForm()
{	
    var stOrgIpAdress = getValue('Orgin');
    var stDesIpAdress = getValue('Destination');
	var stVersion = getValue("IPVersion");

    if(true != IpFilterDescpChk())
    {
        return false;
    }

	if(stVersion == '4')
	{
		if(stOrgIpAdress != '')
		{
			var Orgiplist = stOrgIpAdress.split("/");

			if(Orgiplist[0] != "" && isAbcIpAddress(Orgiplist[0]) == false)
			{
				AlertEx(ipincoming_language['bbsp_originaddr'] + stOrgIpAdress + ipincoming_language['bbsp_isvalid']);
				return false;
			}
			
			if(Orgiplist.length == 2)
			{
				if (isNaN(Orgiplist[1]) == true || parseInt(Orgiplist[1],10) <= 0 || parseInt(Orgiplist[1],10) > 32 || isNaN(Orgiplist[1].replace(' ', 'a')) == true)
				{
					AlertEx(ipincoming_language['bbsp_originaddr'] + stOrgIpAdress + ipincoming_language['bbsp_isvalid']);
					return false;     
				}
			}
			
		}

		if(stDesIpAdress != '')
		{
			var Desiplist = stDesIpAdress.split("/");

			if(Desiplist[0] != "" && isAbcIpAddress(Desiplist[0]) == false)
			{
				AlertEx(ipincoming_language['bbsp_destaddr'] + stDesIpAdress + ipincoming_language['bbsp_isvalid']);
				return false;
			}
			if(Desiplist.length == 2)
			{
				if (isNaN(Desiplist[1]) == true || parseInt(Desiplist[1],10) <= 0 || parseInt(Desiplist[1],10) > 32 || isNaN(Desiplist[1].replace(' ', 'a')) == true)
				{
					AlertEx(ipincoming_language['bbsp_destaddr'] + stDesIpAdress + ipincoming_language['bbsp_isvalid']);
					return false;     
				}
			}
			
		}
	}
	else
	{
		if(stOrgIpAdress != '')
		{
			var Orgiplist = stOrgIpAdress.split("/");
			if(Orgiplist[0] != "" && IsIPv6AddressValid(Orgiplist[0]) == false)
			{
				AlertEx(ipincoming_language['bbsp_originaddr'] + stOrgIpAdress + ipincoming_language['bbsp_isvalid']);
				return false;
			}
			if(Orgiplist.length == 2)
			{
				if (isNaN(Orgiplist[1]) == true || parseInt(Orgiplist[1],10) <= 0 || parseInt(Orgiplist[1],10) > 128 || isNaN(Orgiplist[1].replace(' ', 'a')) == true)
				{
					AlertEx(ipincoming_language['bbsp_originaddr'] + stOrgIpAdress + ipincoming_language['bbsp_isvalid']);
					return false;     
				}
			}
			
		}

		if(stDesIpAdress != '')
		{
			var Desiplist = stDesIpAdress.split("/");

			if(Desiplist[0] != "" && IsIPv6AddressValid(Desiplist[0]) == false)
			{
				AlertEx(ipincoming_language['bbsp_destaddr'] + stDesIpAdress + ipincoming_language['bbsp_isvalid']);
				return false;
			}
			if(Desiplist.length == 2)
			{
				if (isNaN(Desiplist[1]) == true || parseInt(Desiplist[1],10) <= 0 || parseInt(Desiplist[1],10) > 128 || isNaN(Desiplist[1].replace(' ', 'a')) == true)
				{
					AlertEx(ipincoming_language['bbsp_destaddr'] + stDesIpAdress + ipincoming_language['bbsp_isvalid']);
					return false;     
				}
			}
			
		}
	}
	
    if(true != IpFilterPortValidChk())
    {
        return false;
    }

    if(true != IpFilterRepeateCfgChk())
    {
        return false;
    }

	if ((FilterInRule.length >= 31 + 1)&&(getValue('Protocol') == "TCP/UDP"))
	{
		setDisplay('ConfigForm', 0);
		AlertEx(ipincoming_language['bbsp_ipfilterfull']);
        return false;
	}
   	return true;
}

function AddFirstParam(stDescription, ExsitFilterPath, stInterface, stProtocol,
					   stType, stAction, stVersion, orgip, orgmask, stOrgStartPort,
					   stOrgEndPort, desip, desmask, stDesStartPort, stDesEndPort, stEnabled, stDefaultAction)
{
	var urlpath = '';
	var ajaxFilterInTemp = '';
	if ((ExsitFilterPath == '') && (selctIndex == -1))
	{
		urlpath = 'addcfg.cgi?GROUP_a_x=InternetGatewayDevice.X_HW_TDE_Firewall.Firewall' + '&GROUP_a_y=GROUP_a_x.Rule'
		   + '&RequestFile=html/bbsp/ipincoming/ipincomingtde.asp';
	}
	else
	{
		urlpath = "addcfg.cgi?GROUP_a_y=" + ExsitFilterPath + ".Rule" + '&RequestFile=' + 'html/bbsp/ipincoming/ipincomingtde.asp';

	}

	
	var Onttoken = getValue('onttoken');


	if ((ExsitFilterPath == '') && (selctIndex == -1))
	{
		$.ajax({
		type : "POST",
		async : false,
		cache : false,
		data : 'GROUP_a_x.Name='+ stDescription + '&GROUP_a_x.Interface=' + stInterface + '&GROUP_a_x.Type=' + stType + '&GROUP_a_x.DefaultAction=' + stDefaultAction + '&GROUP_a_x.IPVersion=' + stVersion + '&GROUP_a_y.Enabled=' + stEnabled + '&GROUP_a_y.Protocol=' + stProtocol 
		      + '&GROUP_a_y.Action=' + stAction + '&GROUP_a_y.X_HW_PrivateFlag=0' 
		      + '&GROUP_a_y.X_HW_OrgIPAddress=' + orgip + '&GROUP_a_y.X_HW_OrgMask=' + orgmask + '&GROUP_a_y.X_HW_OrgStartPort=' + stOrgStartPort + '&GROUP_a_y.X_HW_OrgEndPort=' + stOrgEndPort
		      + '&GROUP_a_y.X_HW_DstIPAddress=' + desip + '&GROUP_a_y.X_HW_DstMask=' + desmask + '&GROUP_a_y.X_HW_DstStartPort=' + stDesStartPort + '&GROUP_a_y.X_HW_DstEndPort=' + stDesEndPort + '&x.X_HW_Token=' + Onttoken,
		url :  urlpath,
		error:function(XMLHttpRequest, textStatus, errorThrown) 
		{
			if(XMLHttpRequest.status == 404)
			{
			}
		}
		});
	}
	else
	{
		$.ajax({
		type : "POST",
		async : false,
		cache : false,
		data : '&GROUP_a_y.Enabled=' + stEnabled + '&GROUP_a_y.Protocol=' + stProtocol 
		      + '&GROUP_a_y.Action=' + stAction + '&GROUP_a_y.X_HW_PrivateFlag=0' 
		      + '&GROUP_a_y.X_HW_OrgIPAddress=' + orgip + '&GROUP_a_y.X_HW_OrgMask=' + orgmask + '&GROUP_a_y.X_HW_OrgStartPort=' + stOrgStartPort + '&GROUP_a_y.X_HW_OrgEndPort=' + stOrgEndPort
		      + '&GROUP_a_y.X_HW_DstIPAddress=' + desip + '&GROUP_a_y.X_HW_DstMask=' + desmask + '&GROUP_a_y.X_HW_DstStartPort=' + stDesStartPort + '&GROUP_a_y.X_HW_DstEndPort=' + stDesEndPort + '&x.X_HW_Token=' + Onttoken,
		url :  urlpath,
		error:function(XMLHttpRequest, textStatus, errorThrown) 
		{
			if(XMLHttpRequest.status == 404)
			{
			}
		}
		});
	}

	
	if ((ExsitFilterPath == '') && (selctIndex == -1))
	{
		$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url :  "./getfirewalldata.asp",
		success : function(data){
			ajaxFilterInTemp = eval(data);
			}
		});
	}
	return ajaxFilterInTemp;
}

function AddFilter(SubmitForm, ExsitFilterPath)
{	
	var url;
	var RulePrefix = "GROUP_a_y";
	
	var stProtocol = getValue('Protocol');
	var stDescription = '';
	var stInterface = getValue('Interface');
	var stType = getValue('Direction');
	var stAction = getValue('Action');
	var stVersion = getValue('IPVersion');
	var stVersionname;

	var stOrgIpAdress = getValue('Orgin');
	var stOrgStartPort = getValue('OrgPortStart');
	var stOrgEndPort = getValue('OrgPortEnd');

	var stDesIpAdress = getValue('Destination');
	var stDesStartPort = getValue('DesPortStart');
	var stDesEndPort = getValue('DesPortEnd');

	var stIcmpType = getValue("ICMPType");
	var stRejectType = getValue("RejectType");
	var stEnabled = getCheckVal("Enabled");
	var orglist = stOrgIpAdress.split("/");
	var deslist = stDesIpAdress.split("/");

	var orgip = '';
	var orgmask = '';
	var desip = '';
	var desmask = '';
	var stDefaultAction = '';
	var FilterInTemp = '';
	
	if(stOrgIpAdress != '')
	{
		orgip = orglist[0];
		if(stVersion == '4')
		{
			orgmask = filtergetmask(orglist[1]);
		}
		else
		{
			orgmask = filtergetmask6(orglist[1]);
		}
	}

	if(stDesIpAdress != '')
	{
		desip = deslist[0];
		if(stVersion == '4')
		{
			desmask = filtergetmask(deslist[1]);
		}
		else
		{
			desmask = filtergetmask6(deslist[1]);
		}
	}

	if(stVersion == '6')
	{
		stVersionname = 'IPv6';
	}
	else
	{
		stVersionname = 'IPv4';
	}
	if((stInterface == 'LAN')||(stInterface == 'WAN'))
	{
		stDescription = stInterface + '_' + stType + '_' + stVersionname;
	}
	else if(stInterface != '')
	{
		stDescription = MakeWanName(getWanOffirewall(stInterface)) + '_' + stType + '_' + stVersionname;
	}


	if((stType == 'In')&&(stInterface != "LAN"))
	{
		stDefaultAction = 'Drop';
	}
	else
	{
		stDefaultAction = 'Permit';
	}

	if((stOrgEndPort == '')&&(stOrgStartPort != ''))
	{
		stOrgEndPort = stOrgStartPort;
	}

	if((stDesEndPort == '')&&(stDesStartPort != ''))
	{
		stDesEndPort = stDesStartPort;
	}
	
	switch(stProtocol)
	{
		case "TCP":
		case "UDP":
			break;
		case "TCP/UDP":
			FilterInTemp = AddFirstParam(stDescription, ExsitFilterPath, stInterface, 'TCP', stType, stAction, stVersion, orgip, orgmask, stOrgStartPort, stOrgEndPort, desip, desmask, stDesStartPort, stDesEndPort, stEnabled, stDefaultAction);
			stProtocol = "UDP";
			if(FilterInTemp != '')
			{
				for (var i = 0; i < FilterInTemp.length - 1; i ++)
				{
					if ((stInterface == FilterInTemp[i].Interface)
						&& (stType == FilterInTemp[i].Type)
						&& (stVersion == FilterInTemp[i].IPVersion))
					{
						ExsitFilterPath = FilterInTemp[i].Domain;
						break;
					}
				}
			}
			break;
		default:
			break;
	}

	if(selctIndex == -1)
	{
		if (ExsitFilterPath == '') 
		{
			SubmitForm.addParameter('GROUP_a_x.Name', stDescription);
		    SubmitForm.addParameter('GROUP_a_x.Interface', stInterface);
			SubmitForm.addParameter('GROUP_a_x.Type', stType);
			SubmitForm.addParameter('GROUP_a_x.IPVersion', stVersion);
			SubmitForm.addParameter('GROUP_a_x.DefaultAction', stDefaultAction);
		}
	}
	
	SubmitForm.addParameter(RulePrefix +'.X_HW_PrivateFlag', '0');
	SubmitForm.addParameter(RulePrefix +'.Enabled', stEnabled);
	
	if (stProtocol != 'ALL')
	{
		SubmitForm.addParameter(RulePrefix +'.Protocol', stProtocol);
	}
	else
	{
		SubmitForm.addParameter(RulePrefix +'.Protocol', '');
	}
	SubmitForm.addParameter(RulePrefix +'.Action', stAction);
	
	SubmitForm.addParameter('GROUP_a_y.X_HW_OrgIPAddress', orgip);
	SubmitForm.addParameter('GROUP_a_y.X_HW_OrgMask', orgmask);
	if (stProtocol != 'ALL')
	{
		SubmitForm.addParameter('GROUP_a_y.X_HW_OrgStartPort', stOrgStartPort);
		SubmitForm.addParameter('GROUP_a_y.X_HW_OrgEndPort', stOrgEndPort);
	}
	else
	{
		SubmitForm.addParameter('GROUP_a_y.X_HW_OrgStartPort', '');
		SubmitForm.addParameter('GROUP_a_y.X_HW_OrgEndPort', '');
	}

	SubmitForm.addParameter('GROUP_a_y.X_HW_DstIPAddress', desip);
	SubmitForm.addParameter('GROUP_a_y.X_HW_DstMask', desmask);
	if (stProtocol != 'ALL')
	{
		SubmitForm.addParameter('GROUP_a_y.X_HW_DstStartPort', stDesStartPort);
		SubmitForm.addParameter('GROUP_a_y.X_HW_DstEndPort', stDesEndPort);
	}
	else
	{
		SubmitForm.addParameter('GROUP_a_y.X_HW_DstStartPort', '');
		SubmitForm.addParameter('GROUP_a_y.X_HW_DstEndPort', '');
	}
	
	if(stProtocol == 'ICMP')
	{
		SubmitForm.addParameter(RulePrefix +'.IcmpType', stIcmpType);
	}
	else
	{
		SubmitForm.addParameter(RulePrefix +'.IcmpType', '');
	}

	if(stAction == 'Reject')
	{
		SubmitForm.addParameter(RulePrefix +'.RejectType', stRejectType);
	}
	else
	{
		SubmitForm.addParameter(RulePrefix +'.RejectType', '');
	}

	if(selctIndex == -1)
	{
		if (ExsitFilterPath == '')
		{
			url = "addcfg.cgi?GROUP_a_x=InternetGatewayDevice.X_HW_TDE_Firewall.Firewall" + "&GROUP_a_y=GROUP_a_x.Rule" + '&RequestFile=' + 'html/bbsp/ipincoming/ipincomingtde.asp';
		}
		else
		{
			url = "addcfg.cgi?GROUP_a_y=" + ExsitFilterPath + ".Rule" + '&RequestFile=' + 'html/bbsp/ipincoming/ipincomingtde.asp';
		}
	}
	else
	{
		var filterdomainid;
		filterdomainid = findFilterInIndex(FilterInRule[selctIndex].Domain);
		url = "complex.cgi?GROUP_a_x=" + FilterIn[filterdomainid].Domain + "&GROUP_a_y=" + FilterInRule[selctIndex].Domain + '&RequestFile=' + 'html/bbsp/ipincoming/ipincomingtde.asp';

	}
	SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
	SubmitForm.setAction(url);
    	
}

function AddSubmitParam(SubmitForm,type)
{
	setDisable('btnApply_ex',1);
	var stInterface = getValue('Interface');
	var stType = getValue('Direction');
	var stVersion = getValue('IPVersion');
	var ExsitFilterPath = '';
	if(selctIndex == -1)
	{
		for (var i = 0; i < FilterIn.length - 1; i ++)
		{
			if ((stInterface == FilterIn[i].Interface)
				&& (stType == FilterIn[i].Type)
				&& ((stVersion == FilterIn[i].IPVersion) || ((FilterIn[i].IPVersion == '') && (stVersion == 4))))
			{
				ExsitFilterPath = FilterIn[i].Domain;
				break;
			}
		}
	}

	AddFilter(SubmitForm, ExsitFilterPath);

}

function CancelValue()
{
    setDisplay("ConfigForm", 0);
	
	if (selctIndex == -1)
    {
        var tableRow = getElement("ipfilter");

        if (tableRow.rows.length == 1)
        {

        }
        else if (tableRow.rows.length == 2)
        {
            addNullInst('IP Incoming Filter');
        }
        else
        {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine('record_0');
        }
    }
}


function setIPv6Prifix()
{
	var stInterface = getValue('Interface');
	var stType = getValue('Direction');
	var stVersion = getValue('IPVersion');

	if(selctIndex == -1)
	{
		setText('Orgin', '');
		setText('Destination', '');
		if(stVersion == '6')
		{
			if((stInterface == 'LAN')&&(stType == 'In'))
			{
				setText('Orgin', Br0IPv6Prefix);		
			}
			else if((stInterface != 'LAN')&&(stType == 'Out'))
			{
				setText('Orgin', Br0IPv6Prefix);	
			}
			else 
			{
				setText('Destination', Br0IPv6Prefix);	
			}
		}
	}
}

function protocalChange(event_invoke)
{   
    var currentPro = getSelectVal('Protocol');
    var currentAction = getSelectVal('Action');
	
	
	if(currentPro != 'ICMP')
	{
		setDisplay("ICMPTypeRow", 0);
		
		if (currentPro == 'ALL')
		{
			setDisplay("OrginPortBias1", 0);
			setDisplay("OrginPortBias2", 0);
			setDisplay("OrgPortStart", 0);
			setDisplay("OrgiPortBias", 0);
			setDisplay("OrgPortEnd", 0);
			setDisplay("DestPortBias1", 0);
			setDisplay("DestPortBias2", 0);
			setDisplay("DesPortStart", 0);
			setDisplay("DesPortEnd", 0);

			setDisplay("tip2", 0);
			setDisplay("tip4", 0);
		}
		else
		{
			setDisplay("OrginPortBias1", 1);
			setDisplay("OrginPortBias2", 1);
			setDisplay("OrgPortStart", 1);
			setDisplay("OrgiPortBias", 1);
			setDisplay("OrgPortEnd", 1);
			setDisplay("DestPortBias1", 1);
			setDisplay("DestPortBias2", 1);
			setDisplay("DesPortStart", 1);
			setDisplay("DesPortEnd", 1);

			setDisplay("tip2", 1);
			setDisplay("tip4", 1);
		}
	}
	else
	{
		setDisplay("ICMPTypeRow", 1);

		setDisplay("OrginPortBias1", 0);
		setDisplay("OrginPortBias2", 0);
		setDisplay("OrgPortStart", 0);
		setDisplay("OrgiPortBias", 0);
		setDisplay("OrgPortEnd", 0);
		setDisplay("DestPortBias1", 0);
		setDisplay("DestPortBias2", 0);
		setDisplay("DesPortStart", 0);
		setDisplay("DesPortEnd", 0);

		setDisplay("tip2", 0);
		setDisplay("tip4", 0);
	}

	if(currentAction == 'Reject')
	{
		setDisplay("RejectTypeRow", 1);
	}
	else
	{
		setDisplay("RejectTypeRow", 0);
	}

	InitRejectTypeList();
}

function versionChange(event_invoke)
{     
    var currentPro = getSelectVal('IPVersion');
	if(currentPro == '4')
	{
		setDisplay("tip1", 1);
		setDisplay("tip5", 0);
		setDisplay("tip3", 1);
		setDisplay("tip6", 0);
	}
	else
	{
		setDisplay("tip1", 0);
		setDisplay("tip5", 1);
		setDisplay("tip3", 0);
		setDisplay("tip6", 1);
	}
	InitIcmpTypeList();
	InitRejectTypeList();
	setIPv6Prifix();
}

function DirectionChange(event_invoke)
{     
	setIPv6Prifix();
}

function IpFilterShowInst()
{
	if(FilterNum ==  0)
    {   
        document.write('<tr id="record_no"' 
    	                + ' class="tabal_01 align_center" onclick="selectLine(this.id);">');
        document.write('<td >--</td>');
        document.write('<td >--</td>');
	    document.write('<td >--</td>'); 
        document.write('<td >--</td>');
        document.write('<td >--</td>');
		document.write('<td >--</td>');
		document.write('<td >--</td>');
        document.write('<td >--</td>');
		document.write('<td >--</td>');
		document.write('<td >--</td>');
		document.write('</tr>');
    }
    else
    {
        for (var i = 0; i < FilterNum; i++)
        {		
			var Enabled = FilterInRule[i].Enabled;

			if (Enabled == "1" || Enabled == 1)
			{
				Enabled = ipincoming_language['bbsp_enabled'];
			}
			else
			{
				Enabled = ipincoming_language['bbsp_disabled'];
			}	
	
			var filterdomainid;
			filterdomainid = findFilterInIndex(FilterInRule[i].Domain);
			var ruleName = FilterIn[filterdomainid].Name;
            if('' == ruleName){
                ruleName = "--"
            }

			var ipversion;
			if(FilterIn[filterdomainid].IPVersion == '6')
			{
				ipversion = 'IPv6';
			}
			else
			{
				ipversion = 'IPv4';
			}

			if((parseInt(FilterInRule[i].X_HW_PrivateFlag) & 0x01) == 1)
			{
				continue;
			}
			var orgmask;
			var desmask;
			if(ipversion == 'IPv4')			
			{
				orgmask = filtergetmaskLength(FilterInOrgin[i].Mask);
				desmask = filtergetmaskLength(FilterInDes[i].Mask);
			}
			else
			{
				orgmask = filtergetmaskLength6(FilterInOrgin[i].Mask);
				desmask = filtergetmaskLength6(FilterInDes[i].Mask);
			}
			            
       		document.write('<tr id="record_' + i 
        	                + '"class="tabal_01 align_center"  onclick="selectLine(this.id);">'); 
            document.write('<td >' + '<input type="checkbox" id = \"rml'+i+'\" name="rml"'  + ' value="' 
        	                     + FilterInRule[i].Domain  + '">' + '</td>');
			document.write('<td >' + Enabled + '&nbsp;</td>');
        	document.write('<td id="rulename_'+i+'" title="'+htmlencode(ruleName)+'">' + GetStringContent(htmlencode(ruleName),20) + '</td>');

			if((FilterIn[filterdomainid].Interface == 'LAN')||(FilterIn[filterdomainid].Interface == 'WAN'))
			{
				document.write('<td >' + FilterIn[filterdomainid].Interface + '&nbsp;</td>');
			}
			else
			{
				var wan;
				wan = getWanOffirewall(FilterIn[filterdomainid].Interface);
				if(wan != "&nbsp;")
				{
					document.write('<td >' + MakeWanName(wan) + '&nbsp;</td>');
				}
				else
				{
					document.write('<td >'+ '&nbsp;</td>');
				}
			}
			document.write('<td >' + FilterIn[filterdomainid].Type + '&nbsp;</td>');
			document.write('<td >' + ipincoming_language[ipversion] + '&nbsp;</td>');

			if (FilterInRule[i].Protocol != '')
			{
				document.write('<td >' + FilterInRule[i].Protocol + '&nbsp;</td>');
			}
			else
			{
				document.write('<td >' + ipincoming_language['ALL'] + '&nbsp;</td>');
			}
			
			document.write('<td >' + FilterInRule[i].Action + '&nbsp;</td>');
	
			if(FilterInOrgin[i].IPAddress != '')
			{
				var tmporgmask = (orgmask !='') ? ('/' + orgmask ) : "";
		
				document.write('<td >' + FilterInOrgin[i].IPAddress + tmporgmask +  '&nbsp;</td>');
			}
			else
			{
				document.write('<td >' + 'any' + '&nbsp;</td>');
			}

			if(FilterInDes[i].IPAddress != '')
			{
				var tmpdesmask = (desmask !='') ? ('/' + desmask ) : "";
	
				document.write('<td >' + FilterInDes[i].IPAddress + tmpdesmask +  '&nbsp;</td>');
			}
			else
			{
				document.write('<td >' + 'any' + '&nbsp;</td>');
			}
			document.write('</tr>');
        
       } 	 
    }
}


function InitRejectTypeList()
{
	var IPVersion = getValue("IPVersion");
	var protocol = getValue("Protocol");
	var List = getElementById("RejectType");
	List.options.length = 0;

	if(IPVersion == '4')
	{
		List.options.add(new Option(ipincoming_language['bbsp_net_unreachable_mh'],"icmp-net-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_host_unreachable_mh'],"icmp-host-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_proto_unreachable_mh'],"icmp-proto-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_port_unreachable_mh'],"icmp-port-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_net_prohibitedmh'],"icmp-net-prohibited"));
		List.options.add(new Option(ipincoming_language['bbsp_host_prohibited_mh'],"icmp-host-prohibited"));
		if((protocol == 'TCP')||(protocol == 'TCP/UDP'))
		{
			List.options.add(new Option(ipincoming_language['bbsp_tcp_reset_mh'],"tcp-reset"));
		}
	}
	else
	{
		List.options.add(new Option(ipincoming_language['bbsp_icmpv6_no_route_to_destination_mh'],"icmpv6-no-route-to-destination"));
		List.options.add(new Option(ipincoming_language['bbsp_icmpv6_administratively_prohibited_mh'],"icmpv6-administratively-prohibited"));
		List.options.add(new Option(ipincoming_language['bbsp_icmpv6_address_unreachable_mh'],"icmpv6-address-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmpv6_port_unreachable_mh'],"icmpv6-port-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmpv6_source_address_failed_mh'],"icmpv6-source-address-failed"));
		List.options.add(new Option(ipincoming_language['bbsp_icmpv6_reject_route_to_destination_mh'],"icmpv6-reject-route-to-destination"));
	}

}

function InitIcmpTypeList()
{
	var IPVersion = getValue("IPVersion");
	var List = getElementById("ICMPType");
	List.options.length = 0;

	if(IPVersion == '4')
	{
		List.options.add(new Option(ipincoming_language['bbsp_icmp_any_mh'],"any"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_echo_relay_mh'],"echo-reply"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_destination_unreachable_mh'],"destination-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_network_unreachable_mh'],"network-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_host_unreachable_mh'],"host-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_protocol_unreachable_mh'],"protocol-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_port_unreachable_mh'],"port-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_fragmentation_needed_mh'],"fragmentation-needed"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_source_route_failed_mh'],"source-route-failed"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_network_unknown_mh'],"network-unknown"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_host_unknown_mh'],"host-unknown"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_network_prohibited_mh'],"network-prohibited"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_host_prohibited_mh'],"host-prohibited"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_tos_network_unreachable_mh'],"tos-network-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_tos_host_unreachable_mh'],"tos-host-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_communication_prohibited_mh'],"communication-prohibited"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_host_precedence_violation_mh'],"host-precedence-violation"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_precedence_cutoff_mh'],"precedence-cutoff"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_source_quench_mh'],"source-quench"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_redirect'],"redirect"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_network_redirect_mh'],"network-redirect"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_host_redirect_mh'],"host-redirect"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_tos_network_redirect_mh'],"TOS-network-redirect"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_echo_request_mh'],"echo-request"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_router_advertisement_mh'],"router-advertisement"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_router_solicitation_mh'],"router-solicitation"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_time_exceeded_mh'],"time-exceeded"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_ttl_zero_during_transit_mh'],"ttl-zero-during-transit"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_ttl_zero_during_reassembly_mh'],"ttl-zero-during-reassembly"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_parameter_problem_mh'],"parameter-problem"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_ip_header_bad_mh'],"ip-header-bad"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_required_option_missing_mh'],"required-option-missing"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_timestamp_request_mh'],"timestamp-request"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_timestamp_reply_mh'],"timestamp-reply"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_address_mask_request_mh'],"address-mask-request"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_tos_host_redirect_mh'],"TOS-host-redirect"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_address_mask_reply_mh'],"address-mask-reply"));
	}
	else
	{
		List.options.add(new Option(ipincoming_language['bbsp_no_route_to_destination'],"no-route-to-destination"));
		List.options.add(new Option(ipincoming_language['bbsp_administratively_prohibited'],"administratively-prohibited"));
		List.options.add(new Option(ipincoming_language['bbsp_beyond_scope_of_source_address'],"beyond-scope-of-source-address"));
		List.options.add(new Option(ipincoming_language['bbsp_address_unreachable'],"port-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_icmp_port_unreachable_mh'],"host-unreachable"));
		List.options.add(new Option(ipincoming_language['bbsp_source_address_fai'],"source-address-failed"));
		List.options.add(new Option(ipincoming_language['bbsp_reject_route_to_destination'],"reject-route-to-destination"));
		List.options.add(new Option(ipincoming_language['bbsp_error_source_routing_header'],"error-source-routing-header"));
		List.options.add(new Option(ipincoming_language['bbsp_packet_too_big'],"packet-too-big"));
		List.options.add(new Option(ipincoming_language['bbsp_time_exceeded'],"time-exceeded"));
		List.options.add(new Option(ipincoming_language['bbsp_hop_limit_exceeded'],"hop-limit-exceeded"));
		List.options.add(new Option(ipincoming_language['bbsp_fragment_reassembly_time_exceeded'],"fragment-reassembly-time-exceeded"));
		List.options.add(new Option(ipincoming_language['bbsp_parameter_problem'],"parameter-problem"));
		List.options.add(new Option(ipincoming_language['bbsp_erroneous_header_field'],"erroneous-header-field"));
		List.options.add(new Option(ipincoming_language['bbsp_unrecognized_next_header_type'],"unrecognized-next-header-type"));
		List.options.add(new Option(ipincoming_language['bbsp_unrecognized_ipv6_option'],"unrecognized-ipv6-option"));
		List.options.add(new Option(ipincoming_language['bbsp_echo_request'],"echo-request"));
		List.options.add(new Option(ipincoming_language['bbsp_echo_reply'],"echo-reply"));
		List.options.add(new Option(ipincoming_language['bbsp_multicast_listener_query'],"multicast-listener-query"));
		List.options.add(new Option(ipincoming_language['bbsp_multicast_listener_report'],"multicast-listener-report"));
		List.options.add(new Option(ipincoming_language['bbsp_multicast_listener_done'],"multicast-listener-done"));
		List.options.add(new Option(ipincoming_language['bbsp_router_solicitation'],"router-solicitation"));
		List.options.add(new Option(ipincoming_language['bbsp_neighbor_solicitation'],"neighbor-solicitation"));
		List.options.add(new Option(ipincoming_language['bbsp_neighbor_advertisement'],"neighbor-advertisement"));
		List.options.add(new Option(ipincoming_language['bbsp_redirect_message'],"redirect-message"));
		List.options.add(new Option(ipincoming_language['bbsp_router_renumbering'],"router-renumbering"));
		List.options.add(new Option(ipincoming_language['bbsp_router_renumbering_command'],"router-renumbering-command"));
		List.options.add(new Option(ipincoming_language['bbsp_router_renumbering_result'],"router-renumbering-result"));
		List.options.add(new Option(ipincoming_language['bbsp_sequence_numberreset'],"sequence-numberreset"));
		List.options.add(new Option(ipincoming_language['bbsp_node_information_query'],"node-information-query"));
		List.options.add(new Option(ipincoming_language['bbsp_node_information_response'],"node-information-response"));
		List.options.add(new Option(ipincoming_language['bbsp_inverse_neighbor_discovery_solicitation'],"inverse-neighbor-discovery-solicitation"));
		List.options.add(new Option(ipincoming_language['bbsp_inverse_neighbor_discoveryadvertisement'],"inverse-neighbor-discoveryadvertisement"));
		List.options.add(new Option(ipincoming_language['bbsp_version2_multicast_listener_report'],"version2-multicast-listener-report"));
		List.options.add(new Option(ipincoming_language['bbsp_multicast_router_advertisement'],"multicast-router-advertisement"));
		List.options.add(new Option(ipincoming_language['bbsp_multicast_router_solicitation'],"multicast-router-solicitation"));
		List.options.add(new Option(ipincoming_language['bbsp_multicast_router_termination'],"multicast-router-termination"));
	}

}

function InitProtocolList(mode)
{
	var List = getElementById("Protocol");
	List.options.length = 0;

	if(mode == '1')
	{
		List.options.add(new Option(ipincoming_language['TCPUDP'],"TCP/UDP"));
	}
	List.options.add(new Option(ipincoming_language['TCP'],"TCP"));
	List.options.add(new Option(ipincoming_language['UDP'],"UDP"));
	List.options.add(new Option(ipincoming_language['ICMP'],"ICMP"));
	List.options.add(new Option(ipincoming_language['ALL'],"ALL"));
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<div id="ConfigForm1"style="display:inline"> 
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("ipincoming", GetDescFormArrayById(ipincoming_language, "bbsp_mune_tde"), GetDescFormArrayById(ipincoming_language, "bbsp_ipincoming_title"), false);
</script>


<div id="FirewallListTable" style="overflow-x:auto;overflow-y:hidden;width:100%;">   
<script language="JavaScript" type="text/javascript">
writeTabCfgHeader('IP Incoming Filter',"100%","140");
</script>
  <table class="tabal_bg" id="ipfilter" width="100%" border="0" align="center" cellpadding="0" cellspacing="1"> 
    <tr class=" head_title"> 
      <td >&nbsp;</td> 
      <td BindText='bbsp_enable'></td>
      <td BindText='tip_rule_name2'></td>      
	  <td BindText='bbsp_interface'></td>
	  <td BindText='bbsp_direction_tde'></td>
      <td BindText='bbsp_ipversion'></td>
	  <td BindText='bbsp_protocol'></td>
	  <td BindText='bbsp_action'></td>
	  <td BindText='bbsp_orgin'></td>
	  <td BindText='bbsp_destionnation'></td>
    </tr> 
    <script language="JavaScript" type="text/javascript">
	    IpFilterShowInst();
    </script> 
  </table> 
</div>

<div id="ConfigForm" style="display:none"> 
<div class="list_table_spread"></div>
<form id="ConfigurationForm" name="ConfigurationForm">
<table id="ConfigurationFormPanel" cellpadding="2" cellspacing="0" width="100%">
<li id="Enabled" RealType="CheckBox" DescRef="bbsp_enable_rulemh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Empty" Elementclass="SelectDdns" InitValue="Empty" />
<li id="Interface" RealType="DropDownList" DescRef="bbsp_interfacemh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Interface" Elementclass="SelectDdns" InitValue="Empty" ClickFuncApp="onchange=DirectionChange" />
<li id="Direction" RealType="DropDownList" DescRef="bbsp_directionmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Type" Elementclass="SelectDdns" InitValue="[{TextRef:'Incoming',Value:'In'},{TextRef:'Outgoing',Value:'Out'}]" ClickFuncApp="onchange=DirectionChange"/>
<li id="IPVersion" RealType="DropDownList" DescRef="bbsp_ipversionmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="IPVersion" Elementclass="SelectDdns" InitValue="[{TextRef:'IPv4',Value:'4'},{TextRef:'IPv6',Value:'6'}]" ClickFuncApp="onchange=versionChange"/>
<li id="Protocol" RealType="DropDownList" DescRef="bbsp_protocolmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Protocol" Elementclass="SelectDdns" InitValue="[{TextRef:'TCPUDP',Value:'TCP/UDP'},{TextRef:'TCP',Value:'TCP'},{TextRef:'UDP',Value:'UDP'},{TextRef:'ICMP',Value:'ICMP'}]" ClickFuncApp="onchange=protocalChange" />
<li id="ICMPType" RealType="DropDownList" DescRef="bbsp_icmptypemh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="IcmpType" InitValue="Empty"  />
<li id="Action" RealType="DropDownList" DescRef="bbsp_actionmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Action" Elementclass="SelectDdns" InitValue="[{TextRef:'Permit',Value:'Permit'},{TextRef:'Drop',Value:'Drop'},{TextRef:'Reject',Value:'Reject'}]" ClickFuncApp="onchange=protocalChange"/>
<li id="RejectType" RealType="DropDownList" DescRef="bbsp_rejectmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="RejectType" InitValue="Empty" />
<li id="Orgin" RealType="TextOtherBox" DescRef="bbsp_orginmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Origin" MaxLength="63" InitValue="[{Type:'span',Item:[{AttrName:'id',AttrValue:'OrginPortBias1'},{AttrName:'innerhtml', AttrValue:'bbsp_info'}]},{Type:'text',Item:[{AttrName:'id',AttrValue:'OrgPortStart'},{AttrName:'MaxLength', AttrValue:'8'},{AttrName:'class', AttrValue:'width_40px'}]},
{Type:'span',Item:[{AttrName:'id',AttrValue:'OrginPortBias2'},{AttrName:'innerhtml', AttrValue:'bbsp_dash'}]}, {Type:'text',Item:[{AttrName:'id',AttrValue:'OrgPortEnd'},{AttrName:'MaxLength', AttrValue:'8'},{AttrName:'class', AttrValue:'width_40px'}]}, {Type:'span',Item:[{AttrName:'id',AttrValue:'tip1'},{AttrName:'innerhtml', AttrValue:'tdeiptip1'}]}, {Type:'span',Item:[{AttrName:'id',AttrValue:'tip5'},{AttrName:'innerhtml', AttrValue:'tdeiptip3'}]}, {Type:'span',Item:[{AttrName:'id',AttrValue:'tip2'},{AttrName:'innerhtml', AttrValue:'tdeiptip2'}]}]"/>    />
<li id="Destination" RealType="TextOtherBox" DescRef="bbsp_destionnationmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Destination" MaxLength="63" InitValue="[{Type:'span',Item:[{AttrName:'id',AttrValue:'DestPortBias1'},{AttrName:'innerhtml', AttrValue:'bbsp_info'}]},{Type:'text',Item:[{AttrName:'id',AttrValue:'DesPortStart'},{AttrName:'MaxLength', AttrValue:'8'},{AttrName:'class', AttrValue:'width_40px'}]},
{Type:'span',Item:[{AttrName:'id',AttrValue:'DestPortBias2'},{AttrName:'innerhtml', AttrValue:'bbsp_dash'}]}, {Type:'text',Item:[{AttrName:'id',AttrValue:'DesPortEnd'},{AttrName:'MaxLength', AttrValue:'8'},{AttrName:'class', AttrValue:'width_40px'}]}, {Type:'span',Item:[{AttrName:'id',AttrValue:'tip3'},{AttrName:'innerhtml', AttrValue:'tdeiptip1'}]}, {Type:'span',Item:[{AttrName:'id',AttrValue:'tip6'},{AttrName:'innerhtml', AttrValue:'tdeiptip3'}]}, {Type:'span',Item:[{AttrName:'id',AttrValue:'tip4'},{AttrName:'innerhtml', AttrValue:'tdeiptip2'}]}]"/>    />
</table>
<script>
var TableClassTwo = new stTableClass("table_title width_per20", "table_right width_per80","ltr"); 
var ConfigurationFormList = new Array();
	ConfigurationFormList = HWGetLiIdListByForm("ConfigurationForm",null);
	HWParsePageControlByID("ConfigurationForm",TableClassTwo,ipincoming_language,null);
	WriteOption(0);
</script>	 
  
<table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button"> 
<tr>
<td class='width_per20'></td> 
<td class="table_submit"> 
<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
<input class="ApplyButtoncss buttonwidth_100px" name="btnApply_ex" id= "btnApply_ex" type="button" BindText="bbsp_app" onClick="Submit();"> 
<input class="CancleButtonCss buttonwidth_100px" name="cancelButton" id="cancelButton" type="button" BindText="bbsp_cancel" onClick="CancelValue();"></td> 
</tr> 
</table> 
</form>	
<div style="height:10px;"></div>
  <script language="JavaScript" type="text/javascript">
	ParseBindTextByTagName(ipincoming_language, "input", 2);
  </script>
</div>
</div>

</body>
</html>
