<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<title>DHCP Configure</title>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="JavaScript" type="text/javascript">
var curUserType='<%HW_WEB_GetUserType();%>';
var curCfgModeWord ='<%HW_WEB_GetCfgMode();%>'; 
var sysUserType='0';
var norightslavepool='<%HW_WEB_GetFeatureSupport(FT_NOMAL_NO_RIGHT_SLAVE_POOL);%>';
var conditionpoolfeature ='<%HW_WEB_GetFeatureSupport(BBSP_FT_DHCPS_COND_POOL);%>';
var SonetHN8055QFlag = '<%HW_WEB_GetFeatureSupport(BBSP_FT_SONET_HN8055Q);%>';
var SingtelMode = '<%HW_WEB_GetFeatureSupport(BBSP_FT_SINGTEL);%>'; 
var RosMode = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_ROS);%>';
var LanAddrSplitFlag = '<%HW_WEB_GetFeatureSupport(FT_LAN_SPLIT_ADDR_ADRESSPOOL);%>';
var gstwfpoolfeature ='<%HW_WEB_GetFeatureSupport(FT_LAN_GUESTWIFI_POOL);%>';
if('1' == gstwfpoolfeature)
{
   conditionpoolfeature = '0';
}

var specIPoEMTUMax = '<%HW_WEB_GetSPEC(SPEC_LOWER_LAYER_MAX_MTU.UINT32);%>';
var LoginRequestLanguage = '<%HW_WEB_GetLoginRequestLangue();%>';

var ClassAIpSupportFlag='<%HW_WEB_GetFeatureSupport(BBSP_FT_SUPPORT_CLASS_A_IP);%>';
var TDEMode = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_TDE);%>';
function IsSonetHN8055QUser()
{
	if((SonetHN8055QFlag == '1') 
		&& curUserType != '0')
	{
		return true;
	}
	else
	{
		return false;
	}
}

function GetCurrentLoginIP()
{
	var CurUrlIp = (window.location.host).toUpperCase();
	
	return CurUrlIp;
}

function IsSonetNewNormalUser()
{
	if ((('SONET' == curCfgModeWord.toUpperCase()) || ('SONET8045Q' == curCfgModeWord.toUpperCase())) && (curUserType != '0'))
	{
		return true;
	}
	else
	{
		return false;
	}
}

function stLanHostInfo(domain,enable,ipaddr,subnetmask,AddressConflictDetectionEnable)
{
	this.domain = domain;
	this.enable = enable;
	this.ipaddr = ipaddr;
	this.subnetmask = subnetmask;
	this.AddressConflictDetectionEnable = AddressConflictDetectionEnable;
}

function PolicyRouteItem(_Domain, _Type, _VenderClassId, _WanName)
{
    this.Domain = _Domain;
    this.Type = _Type;
    this.VenderClassId = _VenderClassId;
    this.WanName = _WanName;
}

function SlaveDhcpInfo(domain, enable)
{
	this.domain    = domain;
	this.enable    = enable;
}

function GetPolicyRouteListLength(PolicyRouteList, Type)
{
	var Count = 0;

	if (PolicyRouteList == null)
	{
		return 0;
	}

	for (var i = 0; i < PolicyRouteList.length; i++)
	{
		if (PolicyRouteList[i] == null)
		{
			continue;
		}

		if (PolicyRouteList[i].Type == Type)
		{
			Count++;
		}
	}

	return Count;
}
function condhcpst(domain,enable,ipstart,ipend,gateway)
{
	this.Domain 	= domain;
	this.enable 	= enable;
	this.ipstart 	= ipstart;
	this.ipend   	= ipend;
	this.gateway    = gateway;
}
function madhcpst(domain,ipstart,ipend,gateway)
{
	this.Domain 	= domain;
	this.ipstart 	= ipstart;
	this.ipend   	= ipend;
	this.gateway    = gateway;	
}	
function dhcpmainst(domain, DHCPServerEnable, X_HW_MTU)
{
	this.domain = domain;
	this.X_HW_MTU = X_HW_MTU;
	this.DHCPServerEnable = DHCPServerEnable;
}
var LanHostInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.{i},Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask|X_HW_AddressConflictDetectionEnable,stLanHostInfo);%>;
var LanHostInfo2 = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2,Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask|X_HW_AddressConflictDetectionEnable,stLanHostInfo);%>;
var PolicyRouteListAll = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterPolicyRoute, InternetGatewayDevice.Layer3Forwarding.X_HW_policy_route.{i},PolicyRouteType|VenderClassId|WanName,PolicyRouteItem);%>;  
var SlaveDhcpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaSlaveDhcpPool, InternetGatewayDevice.X_HW_DHCPSLVSERVER,DHCPEnable,SlaveDhcpInfo);%>;
var LanHostInfo = LanHostInfos[0];
var ConditionDhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.{i}, Enable|MinAddress|MaxAddress|IPRouters,condhcpst);%>; 
if (ConditionDhcpInfos[1] == null)
{
    ConditionDhcpInfos[1] = new condhcpst("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.2", "", "", "", ""); 
}
var MainDhcpRange = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaMainDhcpPool, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement, MinAddress|MaxAddress|IPRouters, madhcpst);%>;  
var MainDhcpPara = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaMainDhcpPool, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement,DHCPServerEnable|X_HW_MTU,dhcpmainst);%>;  

var SlaveIpAddr = "";
var SlaveIpMask = "";
if (LanHostInfos[1] != null)
{
    SlaveEnable = LanHostInfos[1].enable;
	SlaveIpAddr = LanHostInfos[1].ipaddr;
	SlaveIpMask = LanHostInfos[1].subnetmask;
}
else if(LanHostInfos[1] == null && LanHostInfo2[0] != null && '1' == conditionpoolfeature)
{
	SlaveEnable = LanHostInfo2[0].enable;
	SlaveIpAddr = LanHostInfo2[0].ipaddr;
	SlaveIpMask = LanHostInfo2[0].subnetmask;
}

function setAllDisable()
{
	setDisable('ethIpAddress',1);
	setDisable('ethSubnetMask',1);
	setDisable('enableslaveaddress',1);
	setDisable('slaveIpAddress',1);
	setDisable('slaveSubnetMask',1);
	setDisable('btnApply',1);
	setDisable('cancelValue',1);
}

function displayMtu()
{
	if (specIPoEMTUMax != '1500')
	{	
		setDisplay("br0MtuRow", 1);
		document.getElementById("br0MtuRowRemark").innerHTML = "(1-"+ specIPoEMTUMax + ")";
		getElById('br0MtuRowRemark').title = "(1-"+ specIPoEMTUMax + ")";
		if ("ARABIC" == LoginRequestLanguage.toUpperCase())
		{
			document.getElementById("br0MtuRowRemark").innerHTML = "("+ specIPoEMTUMax + "-1)";
			getElById('br0MtuRowRemark').title = "("+ specIPoEMTUMax + "-1)";    
		}
	}
	else
	{
		setDisplay("SetMTU", 0);
	}
	return;
}

function LoadFrame() 
{
    with ( document.forms[0] ) 
    {
		setText('ethIpAddress',LanHostInfo.ipaddr);
		setText('ethSubnetMask',LanHostInfo.subnetmask);
		setCheck('enableFreeArp', LanHostInfo.AddressConflictDetectionEnable);
		
		if(MainDhcpPara[0] != null)
		{
			setText('br0MtuRow', MainDhcpPara[0].X_HW_MTU);
		}
		
		if (LanHostInfos[1] != null)
		{
		    setCheck('enableslaveaddress',LanHostInfos[1].enable);
			setText('slaveIpAddress', LanHostInfos[1].ipaddr);
			setText('slaveSubnetMask',LanHostInfos[1].subnetmask);
		}
		else if(LanHostInfos[1] == null && LanHostInfo2[0] != null && '1' == conditionpoolfeature)
		{
			setCheck('enableslaveaddress',LanHostInfo2[0].enable);
			setText('slaveIpAddress', LanHostInfo2[0].ipaddr);
			setText('slaveSubnetMask',LanHostInfo2[0].subnetmask);
		}
		
		if ((('TELECOM' == curCfgModeWord.toUpperCase()) && (curUserType != sysUserType))
            || (GetCfgMode().PTVDFB == "1"))
		{
			setAllDisable();
		}
		
		if(("1" == GetCfgMode().TELMEX) || (GetCfgMode().PCCWHK == "1") || ("1" == GetCfgMode().DT_HUNGARY)
	       || ((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY"))
		   ||((curUserType != sysUserType) && ("1" == GetCfgMode().PTVDF))
		   || (true == IsSonetHN8055QUser())
		   || ('1' == RosMode)
		   || (true == IsSonetNewNormalUser()))
	    {
			if(curUserType == sysUserType && GetCfgMode().PCCWHK == "1")
			{
				setDisplay('SecondaryDhcp', 1);
			}
			else
			{
				setDisplay('SecondaryDhcp', 0);
			}
	    }
	    else if (SingtelMode == '1')
	    {
				setDisplay('SecondaryDhcp', 0);	    	
	    }
		else
		{
			setDisplay('SecondaryDhcp', 1);
		}
		configEnableSaddress();
    }
    
    
    if (true == IsSupportConfigFreeArp())
    {   
    	setDisplay('FreeArpForm', 1);
    }
    else
    {
    	setDisplay('FreeArpForm', 0);
    }
    
    displayMtu();
}

function checkMtu()
{

	var br0Mtu = getValue("br0MtuRow");
	if ((br0Mtu!='')&&(false == CheckNumber(br0Mtu, 1, specIPoEMTUMax)))
	{
		AlertEx(dhcp_language['bbsp_MxuInvalid']);
		return false;
	}
	return true;
}

function CheckForm(type) 
{
   var result = false;
   var ethIpAddress = getValue('ethIpAddress');
   var ethSubnetMask = getValue('ethSubnetMask');
   var slaveIpAddress = getValue('slaveIpAddress');
   var slaveSubnetMask = getValue('slaveSubnetMask');


	  if ( isValidIpAddress(ethIpAddress) == false ) {
		 if (SingtelMode == '1')
		 {
			 AlertEx(dhcp_language['bbsp_ipmhaddrp_singtel'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);            
		 }
		 else
		 {
			 AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		 }
		 return false;
	    }
      if ( isValidSubnetMask(ethSubnetMask) == false ) {
        if (SingtelMode == '1')
        {
            AlertEx(dhcp_language['bbsp_subnetmaskmh_singtel'] + ethSubnetMask + dhcp_language['bbsp_isinvalidp']);
        }
        else
        {
            AlertEx(dhcp_language['bbsp_subnetmaskmh'] + ethSubnetMask + dhcp_language['bbsp_isinvalidp']);        
        }
        return false;
      }
	  if (ClassAIpSupportFlag != 1)
      {
      	if ( isMaskOf24BitOrMore(ethSubnetMask) == false ) 
      	{
        	if (SingtelMode == '1')
        	{
            	AlertEx(dhcp_language['bbsp_subnetmaskmh_singtel'] + ethSubnetMask + dhcp_language['bbsp_isinvalidp']);        
        	}
        	else
        	{
            	AlertEx(dhcp_language['bbsp_subnetmaskmh'] + ethSubnetMask + dhcp_language['bbsp_isinvalidp']);
        	}
        	return false;
      	 }
	  }
      
      if(isHostIpWithSubnetMask(ethIpAddress, ethSubnetMask) == false)
      {
        if (SingtelMode == '1')
        {
            AlertEx(dhcp_language['bbsp_ipmhaddrp_singtel'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);            
        }
        else
        {
            AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
        }
        
        return false;
      }
      if ( isBroadcastIp(ethIpAddress, ethSubnetMask) == true ) {
        if (SingtelMode == '1')
        {
            AlertEx(dhcp_language['bbsp_ipmhaddrp_singtel'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);       
        }
        else
        {
            AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
        }
        
        return false;
      }

	  if ('1' == TDEMode)
	  {
			if (false == isSameSubNet(MainDhcpRange[0].ipstart, ethSubnetMask, MainDhcpRange[0].ipend, ethSubnetMask))
	        {
	            AlertEx(dhcp_language['bbsp_conditioncheck_tde']);
	            return false;
	        }
			
			if (false == isSameSubNet(MainDhcpRange[0].ipstart, ethSubnetMask, MainDhcpRange[0].gateway, ethSubnetMask))
	        {
	            AlertEx(dhcp_language['bbsp_conditioncheck_tde']);
	            return false;
	        }
		
			if (false == isSameSubNet(MainDhcpRange[0].gateway, ethSubnetMask, MainDhcpRange[0].ipend, ethSubnetMask))
	        {
	            AlertEx(dhcp_language['bbsp_conditioncheck_tde']);
	            return false;
	        }
		
	  }
      if(("1" == GetCfgMode().TELMEX) 
	      || ((GetCfgMode().PCCWHK == "1") && (curUserType != sysUserType)) 
		  || ("1" == GetCfgMode().DT_HUNGARY)
          || ((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY"))
          ||((curUserType != sysUserType) && ("1" == GetCfgMode().PTVDF))
		  || ('1' == RosMode)		  
		  || (true == IsSonetHN8055QUser())
		  || (true == IsSonetNewNormalUser()))
	  {
	  }
	  else if (SingtelMode == '1')
	  {
	  }
	  else 
	  {	
		 if ((getCheckVal('enableslaveaddress') == 1 &&  '1' == TDEMode) 
			||('1' != TDEMode))
		 {
			 if ( isValidIpAddress(slaveIpAddress) == false ) {
				 AlertEx(dhcp_language['bbsp_ipaddrp'] + slaveIpAddress + dhcp_language['bbsp_isinvalidp']);
				 return false;
			  }
			  if ( isValidSubnetMask(slaveSubnetMask) == false ) {
				 AlertEx(dhcp_language['bbsp_subnetmaskp'] + slaveSubnetMask + dhcp_language['bbsp_isinvalidp']);
				 return false;
			  }
               if (ClassAIpSupportFlag != 1)
               {
                    if ( isMaskOf24BitOrMore(slaveSubnetMask) == false ) 
                    {
                        AlertEx(dhcp_language['bbsp_subnetmaskp'] + ethSubnetMask + dhcp_language['bbsp_isinvalidp']);
                        return false;
                    }
			  }
			  
			  if(isHostIpWithSubnetMask(slaveIpAddress, slaveSubnetMask) == false)
			  {
				  AlertEx(dhcp_language['bbsp_ipaddrp'] + slaveIpAddress + dhcp_language['bbsp_isinvalidp']);
				  return false;
			  }
			  if ( isBroadcastIp(slaveIpAddress, slaveSubnetMask) == true ) {
				 AlertEx(dhcp_language['bbsp_ipaddrp'] + slaveIpAddress + dhcp_language['bbsp_isinvalidp']);
				 return false;
			  }
		 }
		 
		 
	  }
	  
	if(SlaveDhcpInfos[0] != null)
	{
		 if ((1 == SlaveDhcpInfos[0].enable &&  '1' == TDEMode) 
			||('1' != TDEMode))
		{
			if((0 == LanAddrSplitFlag && 1 == SlaveDhcpInfos[0].enable) || (1 == LanAddrSplitFlag && 1 == getCheckVal('enableslaveaddress')))
			{
				  if (slaveIpAddress == ethIpAddress) 
				  {
					  AlertEx(dhcp_language['bbsp_pridhcpsecdhcp']);		  
					  return false;
				  }
						
				  if(true==isSameSubNet(ethIpAddress, ethSubnetMask,slaveIpAddress,slaveSubnetMask))
				  {
					  AlertEx(dhcp_language['bbsp_pridhcpsecdhcp']);		
					  return false;
				  }
			}
		}
	  	
	  }

	  if(( getValue('ethIpAddress').split(".")[3] > 127 ) && ( GetCfgMode().PCCWHK == "1" ) && (curUserType != sysUserType))
	  {
		  AlertEx(dhcp_language['bbsp_iprangeinvalid']);
          return false;   				
	  }

	if (false == checkMtu())
	{
		return false;
	}

    var Reboot = (GetPolicyRouteListLength(PolicyRouteListAll, "SourceIP") > 0 && getValue('ethIpAddress') != LanHostInfos[0].ipaddr) ? dhcp_language['bbsp_resetont']:"";

	result = true;
	if (((getValue('ethIpAddress') != LanHostInfos[0].ipaddr) && (GetCurrentLoginIP() == LanHostInfos[0].ipaddr))
		||((getValue('slaveIpAddress') != SlaveIpAddr) && (GetCurrentLoginIP() == SlaveIpAddr)))
	{
		result = ConfirmEx(dhcp_language['bbsp_dhcpconfirmnote']+Reboot);
	}
	
	if (1 == ClassAIpSupportFlag)
	{
		for (var i = 0;i < GetWanList().length;i++)
		{
			var CurrentWan = GetWanList()[i];
			if (CurrentWan.IPv4IPAddress != '0.0.0.0' && CurrentWan.IPv4SubnetMask != '0.0.0.0'
				&& CurrentWan.IPv4IPAddress != '' && CurrentWan.IPv4SubnetMask != '' )
			{
				if (getValue('ethIpAddress') == CurrentWan.IPv4IPAddress)
				{
					AlertEx(dhcp_language['bbsp_ipdifwan']);
					return false;
				}
				
				if (CurrentWan.IPv4Enable == "1")
				{
					if(true==isSameSubNet(getValue('ethIpAddress'), getValue('ethSubnetMask'),
										  CurrentWan.IPv4IPAddress, CurrentWan.IPv4SubnetMask))
					{
						  AlertEx(dhcp_language['bbsp_lanwanipcheck']);		
						return false;
					}
					
					if((getCheckVal('enableslaveaddress') == 1)
						&&(true==isSameSubNet(getValue('slaveIpAddress'), getValue('slaveSubnetMask'),
									  CurrentWan.IPv4IPAddress, CurrentWan.IPv4SubnetMask)))
					{
						AlertEx(dhcp_language['bbsp_lanwanipcheck']);		
						return false;
					}
				}
			}
		}
	}

	if ( result == true )
	{
		setDisable('btnApply', 1);
        setDisable('cancelValue', 1);
	}
	
	return result;
}

function IsNeedDelCond2()
{
    if((ConditionDhcpInfos[1].gateway == LanHostInfos[1].ipaddr) &&
	   ((LanHostInfos[1].ipaddr != getValue('slaveIpAddress')) || (LanHostInfos[1].subnetmask != getValue('slaveSubnetMask'))))
	{
	    return true;
	}
	if((ConditionDhcpInfos[1].gateway == LanHostInfos[0].ipaddr) &&
	   ((LanHostInfos[0].ipaddr != getValue('ethIpAddress')) || (LanHostInfos[1].subnetmask != getValue('ethSubnetMask'))))
	{
	    return true;
	}
	return false;
}

function AddSubmitParam(Form,type)
{
	var RequestFile = 'html/bbsp/dhcp/dhcp.asp';
	var enableslave = getCheckVal('enableslaveaddress');
	var url = '';

	if(!(( 'TELECOM' == curCfgModeWord.toUpperCase()) && (curUserType != sysUserType)))
	{
		with (document.forms[0])
		{	 
			Form.addParameter('x.IPInterfaceIPAddress',getValue('ethIpAddress'));
			Form.addParameter('x.IPInterfaceSubnetMask',getValue('ethSubnetMask'));
			if (true == IsSupportConfigFreeArp())
			{
				Form.addParameter('x.X_HW_AddressConflictDetectionEnable',getCheckVal('enableFreeArp'));
				if((1 == norightslavepool) && (curUserType != sysUserType))
				{
					
				}
				else
				{
					Form.addParameter('z.X_HW_AddressConflictDetectionEnable',getCheckVal('enableFreeArp'));
				}
			}
			
			if(("1" == GetCfgMode().TELMEX) || (GetCfgMode().PCCWHK == "1") || ("1" == GetCfgMode().DT_HUNGARY)
	           || ((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY"))
		       ||((curUserType != sysUserType) && ("1" == GetCfgMode().PTVDF))
			   || (true == IsSonetHN8055QUser())
			   || ('1' == RosMode)   
			   || (true == IsSonetNewNormalUser()))
			{
				if(curUserType == sysUserType && GetCfgMode().PCCWHK == "1")
				{
					Form.addParameter('z.Enable',enableslave);
					if (enableslave == '1')
					{
						Form.addParameter('z.IPInterfaceIPAddress',getValue('slaveIpAddress'));
						Form.addParameter('z.IPInterfaceSubnetMask',getValue('slaveSubnetMask'));
					}
					url = 'set.cgi?'
						  + 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1'
						  + '&z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2';
				}
				else
				{
					url = 'set.cgi?'
						  + 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1';
				}
			}
			else if (SingtelMode == '1')
			{
					url = 'set.cgi?'
						  + 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1';	
			}
			else
			{
				Form.addParameter('z.Enable',enableslave);
				var isSetGst = true;
				if('1' == gstwfpoolfeature)
			    {
				    if(true == IsNeedDelCond2())
				    {
						var ParameterList = '';
	                    var Url = '/complexajax.cgi?&Del_w=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.2' ;//;&RequestFile=html/bbsp/dhcp/dhcp.asp' ;
	                    HWGetAction(Url, ParameterList, getValue('onttoken'));					
						isSetGst = false;						
					}
					if((isSetGst == true) && (ConditionDhcpInfos[1].gateway == LanHostInfos[1].ipaddr))
                    {					    
						if(ConditionDhcpInfos[0].enable == '1')
						{
						    Form.addParameter('w.Enable',enableslave);
						}
					    else
						{
						    Form.addParameter('w.Enable',ConditionDhcpInfos[0].enable);
						}
						if((enableslave == '1') && (ConditionDhcpInfos[0].enable == '1'))
						{
						    Form.addParameter('w.MinAddress',ConditionDhcpInfos[1].ipstart);
							Form.addParameter('w.MaxAddress',ConditionDhcpInfos[1].ipend);
						}
				    }
			    }
			    if (enableslave == '1')
			    {
					if (LanHostInfo2[0] == null)
                    {
						$.ajax({
							 type : "POST",
							 async : false,
							 cache : false,
							 data : "z.IPInterfaceIPAddress="+getValue('slaveIpAddress')+"&z.IPInterfaceSubnetMask="+getValue('slaveSubnetMask')+"&z.Enable="+enableslave+"&x.X_HW_Token="+getValue('onttoken'),
    							 url : 'add.cgi?'+ 'z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface'+'&RequestFile=html/not_find_file.asp',
							 success : function(data) {
							 },
							 complete: function (XHR, TS) {
								XHR=null;
			 					}
							});
                    }
					else
					{
						Form.addParameter('z.IPInterfaceIPAddress',getValue('slaveIpAddress'));
						Form.addParameter('z.IPInterfaceSubnetMask',getValue('slaveSubnetMask'));
					}
					
					
			    }
				if((isSetGst == true) && ('1' == gstwfpoolfeature))
				{
				   url = 'set.cgi?'
					  + 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1'
					  + '&z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2'
					  + '&w=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.2'	;
				}
				else
				{
				   url = 'set.cgi?'
					  + 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1'
					  + '&z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2';
				}								
			}
			
		}
			
		if ('1500' != specIPoEMTUMax)
		{
			Form.addParameter('y.X_HW_MTU',getValue('br0MtuRow'));
			Form.addParameter('x.X_HW_Token', getValue('onttoken'));
			url +='&y=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement';
		}
		url += '&RequestFile=' + RequestFile;
		
		Form.setAction(url);
	}
	setDisable('dhcpSrvType',1);
}	

var DhcpsFeature = "<% HW_WEB_GetFeatureSupport(BBSP_FT_DHCP_MAIN);%>";

function IsSupportConfigFreeArp()
{
    if(DhcpsFeature == "0")
    {
    	return false;
    }
    
    if((curCfgModeWord.toUpperCase() == 'COMMON') || (curCfgModeWord.toUpperCase() == 'M1'))
    {
	return true;
    }
    
    return false;
}

function CancelConfig()
{
    LoadFrame();
}

function configFreeArp()
{
    var enable = getCheckVal('enableFreeArp');
}

function configEnableSaddress()
{
    var enableslaveaddress = getCheckVal('enableslaveaddress');
	setDisplay('slaveIpAddressRow', enableslaveaddress);
	setDisplay('slaveSubnetMaskRow', enableslaveaddress);
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<script language="JavaScript" type="text/javascript">
	HWCreatePageHeadInfo("dhcptitle", GetDescFormArrayById(dhcp_language, "bbsp_mune"), GetDescFormArrayById(dhcp_language, ""), false);
	if (DhcpsFeature == "1" && bin5board() == false)
	{
	  if (SingtelMode == '1')
	  {
		document.getElementById("dhcptitle_content").innerHTML = dhcp_language['bbsp_dhcp_title']+dhcp_language['bbsp_dhcp_title1_singtel'];
	  }
	  else if (true == IsSupportConfigFreeArp())
	  {
		document.getElementById("dhcptitle_content").innerHTML = dhcp_language['bbsp_dhcp_title']+dhcp_language['bbsp_dhcp_title1']+dhcp_language['bbsp_dhcp_title2'];
	  }
	  else
	  {
		  if('1' == gstwfpoolfeature)
		  {
		      document.getElementById("dhcptitle_content").innerHTML = dhcp_language['bbsp_dhcp_title']+dhcp_language['bbsp_dhcp_title1']+dhcp_language['bbsp_dhcp_title3'];
		  }
		  else
		  {
		      document.getElementById("dhcptitle_content").innerHTML = dhcp_language['bbsp_dhcp_title']+dhcp_language['bbsp_dhcp_title1'];
		  }
	  }
	}
	else
	{
	  document.getElementById("dhcptitle_content").innerHTML = dhcp_language['bbsp_dhcp_title'];
	}
</script> 
<div class="title_spread"></div>

<form id="FreeArpForm" name="FreeArpForm" style="display:none;">
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg"> 
		<li id="enableFreeArp" RealType="CheckBox" DescRef="bbsp_enablefreearpmh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.X_HW_AddressConflictDetectionEnable" InitValue="Empty" InitValue="0"   ClickFuncApp="onclick=configFreeArp"/>
	</table>
	<script>
		var TableClass = new stTableClass("width_per30", "width_per70", "ltr");
		var FreeArpConfigFormList = new Array();
		FreeArpConfigFormList = HWGetLiIdListByForm("FreeArpForm", null);
		HWParsePageControlByID("FreeArpForm", TableClass, dhcp_language, null);
	</script>
	<div id="ConfigFreeArpSpace" class="func_spread"></div>
</form>
  
<form id="DhcpPripoolForm" name="DhcpPripoolForm">
<script language="JavaScript" type="text/javascript">
    if (SingtelMode == '1')
    {
    	document.write('<div id="DhcpPripoolTitle" class="func_title" BindText="bbsp_dhcp_pripool_singtel"></div>');
    }
    else
    {
    	document.write('<div id="DhcpPripoolTitle" class="func_title" BindText="bbsp_dhcp_pripool"></div>');
	}
</script>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<script language="JavaScript" type="text/javascript">
    if (SingtelMode == '1')
    {
		document.write("\<li id=\"ethIpAddress\" RealType=\"TextBox\" DescRef=\"bbsp_ipmh_common_singtel\" RemarkRef=\"Empty\" ErrorMsgRef=\"Empty\" Require=\"TRUE\" BindField=\"x.IPInterfaceIPAddress\"  MaxLength=\"15\" InitValue=\"Empty\" \/\>");
		document.write("\<li id=\"ethSubnetMask\" RealType=\"TextBox\" DescRef=\"bbsp_maskmh_common_singtel\" RemarkRef=\"bbsp_subnetmaskmh_eg_singtel\" ErrorMsgRef=\"Empty\" Require=\"TRUE\" BindField=\"x.IPInterfaceSubnetMask\"  MaxLength=\"15\"  InitValue=\"Empty\" \/\>")
	}
	else
	{
		document.write("\<li id=\"ethIpAddress\" RealType=\"TextBox\" DescRef=\"bbsp_ipmh_common\" RemarkRef=\"Empty\" ErrorMsgRef=\"Empty\" Require=\"TRUE\" BindField=\"x.IPInterfaceIPAddress\"  MaxLength=\"15\" InitValue=\"Empty\" \/\>");
		document.write("\<li id=\"ethSubnetMask\" RealType=\"TextBox\" DescRef=\"bbsp_maskmh_common\" RemarkRef=\"Empty\" ErrorMsgRef=\"Empty\" Require=\"TRUE\" BindField=\"x.IPInterfaceSubnetMask\"  MaxLength=\"15\"  InitValue=\"Empty\" \/\>")
	}
</script>	
	</table>
	<script>
		var DhcpPripoolFormList = new Array();
		DhcpPripoolFormList = HWGetLiIdListByForm("DhcpPripoolForm",null);
		HWParsePageControlByID("DhcpPripoolForm",TableClass,dhcp_language,null);
	</script>
</form>
  
<div id='SecondaryDhcp' style="display:none">
<div class="func_spread"></div>
<form id="SecondaryAddrForm" name="SecondaryAddrForm">
	<div id="SecondaryAddrTitle" class="func_title" BindText="bbsp_dhcp_secpool"></div>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
		<li id="enableslaveaddress" RealType="CheckBox" DescRef="bbsp_enableslaveaddress" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.enable" InitValue="Empty" InitValue="0" ClickFuncApp="onclick=configEnableSaddress"/>
		<li id="slaveIpAddress" RealType="TextBox" DescRef="bbsp_ipslavemh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="TRUE" BindField="x.IPInterfaceIPAddress"  MaxLength="15" InitValue="Empty" />
		<li id="slaveSubnetMask" RealType="TextBox" DescRef="bbsp_maskslavemh" RemarkRef="Empty" ErrorMsgRef="Empty" Require="TRUE" BindField="x.IPInterfaceSubnetMask"  MaxLength="15"  InitValue="Empty" />
	</table>
	<script>
		var DhcpPripoolFormList = new Array();
		DhcpPripoolFormList = HWGetLiIdListByForm("SecondaryAddrForm",null);
		HWParsePageControlByID("SecondaryAddrForm",TableClass,dhcp_language,null);
		if (conditionpoolfeature == '1')
		{
			getElById("enableslaveaddressCol").title = dhcp_language['bbsp_dhcp_con_enable'];
		}
		else
		{
			getElById("enableslaveaddressCol").title = dhcp_language['bbsp_dhcp_slave_enable'];
		}
	</script>
</form>
</div>  

<div id="SetMTU" name="SetMTU">
<div class="func_spread"></div>
<form  id="SetDHCpMTU" name="SetDHCpMTU">
	<div id="SecondaryAddrTitle" class="func_title" BindText="bbsp_dhcp_mtu"></div>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
		<li id="br0MtuRow" RealType="TextBox" DescRef="bbsp_dhcp_mtu" RemarkRef="Empty" ErrorMsgRef="Empty" Require="TRUE" BindField=""  MaxLength="4"  InitValue="Empty" />
	</table>
	<script>
		var DhcpSetMTUFormList = new Array();
		DhcpSetMTUFormList = HWGetLiIdListByForm("SetDHCpMTU",null);
		HWParsePageControlByID("SetDHCpMTU",TableClass,dhcp_language,null);
	</script>
</form>
</div>

<div id='dhcpInfo' style="display:none "> 
    <table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg"> 
      <tr> 
        <td  class="table_title width_per25" BindText='bbsp_startipmh'></td> 
        <td  class="table_right width_per70"> <input type='text' id='dhcpEthStart' name='dhcpEthStart' maxlength='15'> </td> 
      </tr> 
      <tr> 
        <td  class="table_title width_per25" BindText='bbsp_endipmh'></td> 
        <td  class="table_right width_per70"> <input type='text' id='dhcpEthEnd' name='dhcpEthEnd' maxlength='15'> </td> 
      </tr> 
      <tr > 
        <td  class="table_title width_per25" BindText='bbsp_leaseunitmh'></td> 
        <td  class="table_right width_per70"> <input type="text" id="dhcpLeasedTime" name="dhcpLeasedTime" value="1" size="6"> 
          <select id='dhcpLeasedTimeFrag' name='dhcpLeasedTimeFrag' size='1'> 
            <option value='60'><script>document.write(dhcp_language['bbsp_minute']);</script>
            <option value='3600'><script>document.write(dhcp_language['bbsp_hou']);</script>
            <option value='86400'><script>document.write(dhcp_language['bbsp_day']);</script>
            <option value='604800'><script>document.write(dhcp_language['bbsp_week']);</script>
          </select> </td> 
      </tr> 
      <tr  style="display:none "> 
        <td  class="table_title width_per25" BindText='bbsp_devtypemh' ></td> 
        <td  class="table_right width_per70"> <select id='IpPoolIndex' name='IpPoolIndex' size='15' onChange='IpPoolIndexChange()'> 
            <option value='1'><script>document.write(dhcp_language['bbsp_stb']);</script>
            <option value='2'><script>document.write(dhcp_language['bbsp_phone']);</script>
            <option value='3'><script>document.write(dhcp_language['bbsp_camera']);</script>
            <option value='4'><script>document.write(dhcp_language['bbsp_computer']);</script>
          </select> </td> 
      </tr> 
      <tr  style="display:none "> 
        <td  class="table_title width_per25" BindText='bbsp_startipmh'></td> 
        <td  class="table_right width_per70"> <input type='text' id='dhcpEthStartFrag' name='dhcpEthStartFrag' maxlength='15'> </td> 
      </tr> 
      <tr style="display:none "> 
        <td  class="table_title width_per25" BindText='bbsp_endipmh'></td> 
        <td  class="table_right width_per70"> <input type='text' id='dhcpEthEndFrag' name='dhcpEthEndFrag' maxlength='15'> </td> 
      </tr> 
      <tr style="display:none "> 
        <td  class="table_title width_per25" BindText='bbsp_dhcprelaymh'></td> 
        <td  class="table_right width_per70"> <input type='checkbox' id='enableRelay' name='enableRelay'> </td> 
      </tr> 
    </table> 
  </div> 
  <table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button"> 
    <tr > 
      <td class='width_per30'></td> 
      <td class="table_submit"> 
	    <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
	    <button id="btnApply" name="btnApply" type="button" class="ApplyButtoncss buttonwidth_100px"  onClick="Submit(0);"><script>document.write(dhcp_language['bbsp_app']);</script></button> 
        <button name="cancelValue" id="cancelValue" class="CancleButtonCss buttonwidth_100px"  type="button" onClick="CancelConfig();"><script>document.write(dhcp_language['bbsp_cancel']);</script></button> </td> 
    </tr> 
  </table> 
  <br> 
<script>
	ParseBindTextByTagName(dhcp_language, "td",    1);
	ParseBindTextByTagName(dhcp_language, "div",   1);
</script>
</body>
</html>
