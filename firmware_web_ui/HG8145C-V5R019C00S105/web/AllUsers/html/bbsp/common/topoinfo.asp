function TopoInfoClass(Domain, EthNum, SSIDNum)
{   
    this.Domain = Domain;
    this.EthNum = EthNum;
    this.SSIDNum = SSIDNum;
}

var TopoInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_Topo,X_HW_EthNum|X_HW_SsidNum,TopoInfoClass);%>
var TopoInfo = TopoInfoList[0];
if('<%GetLanPortNum();%>' != "" && '<%GetLanPortNum();%>' != null)
{
	TopoInfo.EthNum = '<%GetLanPortNum();%>';
}

function GetTopoInfo()
{
    return TopoInfo;
}
function GetTopoItemValue(Name)
{
    return TopoInfo[Name];
}

function LanInfoClass(domain, Name, L3Enable, Mode, Vlan, MultiCastVlanAct, MultiCastVlan)
{
	this.domain = domain;
	this.Name = Name;
	this.L3Enable = L3Enable;
	this.Mode = Mode;
	if(Mode == 1)
		this.Vlan = Vlan.replace(/;/g, ",");
	else
		this.Vlan = "";
	this.PortName = '';
	this.MultiCastVlanAct = MultiCastVlanAct;
    this.MultiCastVlan = MultiCastVlan;
}

var LanArray = new Array();
var LanArrayExt = new Array();
var __LanArray = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.{i},Name|X_HW_L3Enable|X_HW_Mode|X_HW_VLAN|X_HW_MultiCastVlanAct|X_HW_MultiCastVlan,LanInfoClass);%>;
var isOpticUpMode = '<%HW_WEB_IsOpticUpMode();%>';
var iponlyflg ='<%HW_WEB_GetFeatureSupport(HW_AMP_FT_IPONLY);%>';

var _LanPortNum = ((__LanArray.length - 1) > GetTopoInfo().EthNum) ? GetTopoInfo().EthNum : (__LanArray.length - 1);

for(var i = 0; i < _LanPortNum; i++)
{
	if(i < 4)
	{
	    __LanArray[i].PortName = 'LAN' + __LanArray[i].domain.charAt(__LanArray[i].domain.length-1);
	}
	else
	{
		 __LanArray[i].PortName = (iponlyflg > 0) ? "EXT1" : ('LAN' + __LanArray[i].domain.charAt(__LanArray[i].domain.length-1)); 
	}
	LanArray.push(__LanArray[i]);
	LanArrayExt.push(__LanArray[i]);
}

if(_LanPortNum <  __LanArray.length - 1)
{
    for(var i = _LanPortNum; i < __LanArray.length - 1; i++)
	{
	    __LanArray[i].PortName = 'EXT1';
		LanArrayExt.push(__LanArray[i]);
	}	
}

function InitPortList(ListControlId)
{
    var Control = getElById(ListControlId);

    for (var i = 0; i < LanArray.length; i++)
    {
        var Option = document.createElement("Option");
        Option.value = LanArray[i].domain;
        Option.innerText = LanArray[i].PortName;
        Option.text = LanArray[i].PortName;
        Control.appendChild(Option);
    }
}

function GetLanListInfo()
{
    return LanArrayExt;
}

function GetLanDomainByName(currentPort)
{
    var portarray = GetLanListInfo();
	var portDomain = '';
	for(var i = 0; i < portarray.length; i++)
	{
	    if(currentPort == portarray[i].PortName )
		{
		    portDomain = portarray[i].domain;
			break;
		}
	}
	return portDomain;
}

function GetLanNameByDomain(currentDomain)
{
    var portarray = GetLanListInfo();
	var CurrportName = '';
	for(var i = 0; i < portarray.length; i++)
	{
	    if(currentDomain == portarray[i].domain )
		{
		    CurrportName = portarray[i].PortName;
			break;
		}
	}
	return CurrportName;
}


function getTianYilandesc(lanid)
{
	var acEthType = '<%HW_WEB_GetEthTypeList();%>';
	var portNum = 0;
	
	portNum = parseInt(acEthType.charAt(0), 10);	
	if(lanid > portNum)
	{
		return "";
	}	
	
	return ('1' == acEthType.charAt(lanid))?"百兆口" + lanid : "千兆口" + lanid;
}
