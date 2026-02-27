<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="javascript" src="../common/wlan_list.asp"></script>
<title>WiFi Coverage Management</title>
<script language="JavaScript" type="text/javascript">

var UPNPCfgFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_UPNP_CONFIG);%>';

function LoadResource()
{
    var all = document.getElementsByTagName("td");
    for (var i = 0; i <all.length ; i++) 
    {
        var b = all[i];
        if(b.getAttribute("BindText") == null)
        {
            continue;
        }

        if (wificovercfg_language[b.getAttribute("BindText")]) 
        {
            b.innerHTML = wificovercfg_language[b.getAttribute("BindText")];
        }
    }
}

function stWifiCoverService(domain, AutoExtended, AutoExtendedPolicy, IspExtended, AutoSwitchAP, ForcedSwitchThrehold, ConditionalSwitchThrehold, SyncWifiSwitch, Enable)
{
    this.domain = domain;
    this.AutoExtended = AutoExtended;
	this.AutoExtendedPolicy = AutoExtendedPolicy;
    this.IspExtended = IspExtended;
    this.AutoSwitchAP = AutoSwitchAP;
	this.ForcedSwitchThrehold = ForcedSwitchThrehold;
	this.ConditionalSwitchThrehold = ConditionalSwitchThrehold;
	this.SyncWifiSwitch = SyncWifiSwitch;
    this.Enable = Enable;
}

var WifiCoverService = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_WifiCoverService, AutoExtended|AutoExtendedPolicy|IspExtended|AutoSwitchAP|ForcedSwitchThrehold|ConditionalSwitchThrehold|SyncWifiSwitch|Enable, stWifiCoverService);%>;

function stConfigurationByRadio(domain, RFBand, AutoExtendedSSIDIndex)
{
    this.domain = domain;
    this.RFBand = RFBand;
	this.AutoExtendedSSIDIndex = AutoExtendedSSIDIndex;
}

var ConfigurationByRadio = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_WifiCoverService.ConfigurationByRadio.{i},RFBand|AutoExtendedSSIDIndex,stConfigurationByRadio);%>;

function getInstIdByDomain(domain)
{
    if ('' != domain)
    {
        return parseInt(domain.charAt(domain.length - 1));    
    }
}

function stExtendedWLC(domain, SSIDIndex)
{
    this.domain = domain;
    this.SSIDIndex = SSIDIndex;
    this.ExtWlanInst = getInstIdByDomain(domain);
}

var apExtendedWLC = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}.WifiCover.ExtendedWLC.{i}, SSIDIndex, stExtendedWLC);%>;

function getWlanPortNumber(name)
{
    if ('' != name)
    {
        return parseInt(name.charAt(name.length - 1));    
    }
}

function stWlan(domain, Name, ssid, X_HW_RFBand,LowerLayers,X_HW_ServiceEnable,BeaconType,WPAAuthenticationMode,IEEE11iAuthenticationMode,X_HW_WPAand11iAuthenticationMode)
{
    this.domain = domain;
    this.Name = Name;
    this.ssid = ssid;
	this.X_HW_RFBand = X_HW_RFBand;
    this.LowerLayers = LowerLayers;
	this.X_HW_ServiceEnable = X_HW_ServiceEnable;
	this.BeaconType = BeaconType;
	this.WPAAuthenticationMode = WPAAuthenticationMode;
	this.IEEE11iAuthenticationMode = IEEE11iAuthenticationMode;
	this.X_HW_WPAand11iAuthenticationMode = X_HW_WPAand11iAuthenticationMode;
    this.WlanInst = getInstIdByDomain(domain);
}

var WlanList = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}, Name|SSID|X_HW_RFBand|LowerLayers|X_HW_ServiceEnable|BeaconType|WPAAuthenticationMode|IEEE11iAuthenticationMode|X_HW_WPAand11iAuthenticationMode, stWlan);%>;
var WlanListNum = WlanList.length - 1;

for (var i = 0; i < WlanListNum; i++)
{
    for (var j = i; j < WlanListNum; j++)
    {
        var index_i = getWlanPortNumber(WlanList[i].Name);
        var index_j = getWlanPortNumber(WlanList[j].Name);
        
        if (index_i > index_j)
        {
            var WlanTemp = WlanList[i];
            WlanList[i] = WlanList[j];
            WlanList[j] = WlanTemp;
        }
    }
}

function stFonSsidInst(domain, inst2g, inst5g)
{
    this.domain = domain;
    this.fonssid2g = inst2g;
    this.fonssid5g = inst5g;
}
var fonssidinsts  = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.FON, SSID2GINST|SSID5GINST, stFonSsidInst, EXTEND);%>;
var fonssidinst = new stFonSsidInst("", 0 , 0);
if ((fonssidinsts.length > 1) && ('1' == '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_FON);%>'))
{
    fonssidinst = fonssidinsts[0];
}

function  stApDevice(domain, DeviceType, SerialNumber, DeviceStatus, UpTime, WorkingMode, SyncStatus, SupportedWorkingMode, SupportedRFBand, SupportedSSIDNumber)
{
    this.domain = domain;
    this.DeviceType = DeviceType;
    this.SerialNumber = SerialNumber;
    this.DeviceStatus = DeviceStatus;
    this.UpTime = UpTime;
    this.WorkingMode = WorkingMode;
    this.SyncStatus = SyncStatus;
    this.SupportedWorkingMode = SupportedWorkingMode;
    this.SupportedRFBand = SupportedRFBand;
    this.SupportedSSIDNumber = SupportedSSIDNumber;
}

var apDeviceList = new Array();
apDeviceList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}, DeviceType|SerialNumber|DeviceStatus|UpTime|WorkingMode|SyncStatus|SupportedWorkingMode|SupportedRFBand|SupportedSSIDNumber, stApDevice);%>;
var apNum = apDeviceList.length - 1;

var syncstatus = wificovercfg_language['amp_wificover_syncstatus_yes_desc'];
function getSyncStauts(intSyncStatus)
{
    if (1 == intSyncStatus)
    {
        syncstatus = wificovercfg_language['amp_wificover_syncstatus_nocfg_desc'];
    }
    else if (2 == intSyncStatus)
    {
        syncstatus = wificovercfg_language['amp_wificover_syncstatus_no_desc'];
    }
    else
    {
        syncstatus = wificovercfg_language['amp_wificover_syncstatus_yes_desc'];
    }
}

function UpnpEnableSubmit()
{
    if (true == UPNPCfgFlag)
    {
        var Form = new webSubmitForm();
        Form.addParameter('x.Enable', getCheckVal('UpnpEnable'));
        Form.setAction('set.cgi?'
                    + 'x=' + 'InternetGatewayDevice.X_HW_WifiCoverService'
                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');
                    
        Form.addParameter('x.X_HW_Token', getValue('onttoken'));
        Form.submit();
    }

}

function onClickSelectPolicy()
{		
	if(1 == getRadioVal("AutoExtendedPolicy"))
	{
		WifiCoverService[0].AutoExtended = 0;
	}
	else if(2 == getRadioVal("AutoExtendedPolicy"))
	{
		WifiCoverService[0].AutoExtended = 1;
		WifiCoverService[0].AutoExtendedPolicy = 0
	}
	else if(3 == getRadioVal("AutoExtendedPolicy"))
	{
		WifiCoverService[0].AutoExtended = 1;
		WifiCoverService[0].AutoExtendedPolicy = 1;
	}
	else 
	{
		WifiCoverService[0].AutoExtended = 1;
	}
	
	var Form = new webSubmitForm();

    Form.addParameter('x.AutoExtended', WifiCoverService[0].AutoExtended);
	Form.addParameter('x.AutoExtendedPolicy',WifiCoverService[0].AutoExtendedPolicy);

    Form.setAction('set.cgi?'
                    + 'x=' + 'InternetGatewayDevice.X_HW_WifiCoverService'
                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');
                    
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function funCover2GSsidSelect()
{
    var Form = new webSubmitForm();
    Form.addParameter('x.AutoExtendedSSIDIndex', getSelectVal('Cover2GSsidSelect'));
    Form.setAction('set.cgi?'
                    + 'x=' + 'InternetGatewayDevice.X_HW_WifiCoverService.ConfigurationByRadio.1'
                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');             
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function funCover5GSsidSelect()
{
    var Form = new webSubmitForm();
    Form.addParameter('x.AutoExtendedSSIDIndex', getSelectVal('Cover5GSsidSelect'));
    Form.setAction('set.cgi?'
                    + 'x=' + 'InternetGatewayDevice.X_HW_WifiCoverService.ConfigurationByRadio.2'
                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');
                    
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function CheckSwitchThreodhold()
{ 
    var ForceSwitch = getValue('wifiCoverForceSwitch');
    var ConditionalSwitch = getValue('wifiCoverConditionalSwitch');

    if(!isInteger(ForceSwitch))
    {
        AlertEx(wificovercfg_language['amp_forceSwitch_int']);
        return false;
    }

    if( (parseInt(ForceSwitch,10) < -100) || (parseInt(ForceSwitch,10) > -66) )
    {

        AlertEx(wificovercfg_language['amp_forceSwitch_out_range']);
        return false;
    }

    if(!isInteger(ConditionalSwitch))
    {
        AlertEx(wificovercfg_language['amp_conditionalSwitch_int']);
        return false;
    }

    if( (parseInt(ConditionalSwitch,10) < -84) || (parseInt(ConditionalSwitch,10) > -60) )
    {
        AlertEx(wificovercfg_language['amp_conditionalSwitch_out_range']);
        return false;
    }

    if( parseInt(ForceSwitch,10) > parseInt(ConditionalSwitch,10) )
    {
        AlertEx(wificovercfg_language['amp_force_bigger_conditional']);
        return false;
    }

    return true;
}

function wifiCoverAdvSubmit()
{
    var Form = new webSubmitForm();
	var forcedSwitchThreholdValue = parseInt(getValue('wifiCoverForceSwitch'), 10);
    var coverForceSwitchValue = parseInt(getValue('wifiCoverConditionalSwitch'), 10);
    
    if (false == CheckSwitchThreodhold())
    {
        return;
    }

    Form.addParameter('x.AutoSwitchAP', getCheckVal('AutoSwitchAP'));
    Form.addParameter('x.ForcedSwitchThrehold', forcedSwitchThreholdValue);
    Form.addParameter('x.ConditionalSwitchThrehold', coverForceSwitchValue);

    Form.setAction('set.cgi?'
                    + 'x=' + 'InternetGatewayDevice.X_HW_WifiCoverService'
                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');
                    
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}


function wifiCoverAdvCancel()
{
    setCheck('AutoSwitchAP', WifiCoverService[0].AutoSwitchAP);
	setText('wifiCoverForceSwitch', WifiCoverService[0].ForcedSwitchThrehold);  
    setText('wifiCoverConditionalSwitch', WifiCoverService[0].ConditionalSwitchThrehold);   
}

function IsOnlyOneSsidExtSupport(wificoverApId)
{
    for (var i = 0; i < apNum; i++)
    {
        var ApInst = getInstIdByDomain(apDeviceList[i].domain);
        
        if (wificoverApId != ApInst)
        {
            continue;
        }
        
        if ("WS331c" == apDeviceList[i].DeviceType)
        {
            for (var index = 0; index < WlanListNum; index++)
            {
                var wlanInst = getInstIdByDomain(WlanList[index].domain);
                
                if (IsIspSsid(wlanInst))
                {
                    continue;
                }
                if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                {
                    continue;
                }
				if(1 != WlanList[index].X_HW_ServiceEnable)
				{
					continue;
				}
				
                setDisable('ExtendedWLC_' + wlanInst, 1);
            }
        }
		else
		{
		    for (var index = 0; index < WlanListNum; index++)
            {
			    var wlanInst = getInstIdByDomain(WlanList[index].domain);
                
                if (IsIspSsid(wlanInst))
                {
                    continue;
                }
                if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                {
                    continue;
                }
				if(1 != WlanList[index].X_HW_ServiceEnable)
				{
					continue;
				}
                setDisable('ExtendedWLC_' + wlanInst, 0);
            }
		}
    }
}

var checkwlanInst2G = 0;

function IsOnlyOneSsidExtEveryRFBandSupport(wificoverApId,checkflag,checkwlanInst,rfband)
{ 
	
	var devicetype;

	for (var indexap = 0; indexap < apNum; indexap++)
	{
		var apInst = getInstIdByDomain(apDeviceList[indexap].domain);
		if (apInst == wificoverApId)
		{
			break;
		}
	}
	
	if (apNum == indexap)
	{
		return false;
	}
	
	devicetype = apDeviceList[indexap].DeviceType;
	
	if(("Honor" == devicetype) || ("PT230" == devicetype))
	{
		for (var index = 0; index < WlanListNum; index++)
		{
			var wlanInst = getInstIdByDomain(WlanList[index].domain);
			
			if (IsIspSsid(wlanInst))
			{
				continue ;
			} 
                    if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                    {
                        continue;
                    }
			if(1 != WlanList[index].X_HW_ServiceEnable)
			{
				continue;
			}
			
			if('2.4GHz' == rfband)
			{
				if(-1 != WlanList[index].X_HW_RFBand.indexOf("5G"))  
				{
					continue;
				} 
				
				if((checkwlanInst != wlanInst)&&(checkwlanInst != 0)) 
				{ 
					setDisable('ExtendedWLC_' + wlanInst, 1);
				}
			}
			
			if('5GHz' == rfband)
			{
				if(-1 != WlanList[index].X_HW_RFBand.indexOf("2.4G"))  
				{
					continue;
				} 
				
				if((checkwlanInst != wlanInst)&&(checkwlanInst != 0))  
				{ 
					setDisable('ExtendedWLC_' + wlanInst, 1);
				}
			}
			
		}
	}
}

function IsBandCompatible(Wlanindex, wificoverApId)
{
    var WlanCapability = WlanList[Wlanindex].X_HW_RFBand;

    for (var i = 0; i < apNum; i++)
    {
        var ApInst = getInstIdByDomain(apDeviceList[i].domain);
        
        if (wificoverApId != ApInst)
        {
            continue;
        }
        
        var ApCapability = apDeviceList[i].SupportedRFBand;
        if ( ((-1 != WlanCapability.indexOf("2.4G")) && (-1 != ApCapability.indexOf("2.4G")))
             || ((-1 != WlanCapability.indexOf("5G")) && (-1 != ApCapability.indexOf("5G"))) )
        {
            return true;
        }
    }

    return false;
}


var curWorkMode = '';
function SetApDetail(wificoverApId)
{
    IsOnlyOneSsidExtSupport(wificoverApId);
	
    for (var index = 0; index < WlanListNum; index++)
    {
        var extEnable = 0;
        var wlanInst = getInstIdByDomain(WlanList[index].domain);
		var checkflag = 0;
		var checkwlanInst = 0;
		var rfband = '';
        
        for (var extWlcLoop = 0; extWlcLoop < apExtendedWLC.length - 1; extWlcLoop++)
        {
            var path = "InternetGatewayDevice.X_HW_APDevice.";
            var ApInst = apExtendedWLC[extWlcLoop].domain.charAt(path.length);
            if (wificoverApId != ApInst)
            {
                continue;
            }
            else
            {
                if (wlanInst == apExtendedWLC[extWlcLoop].SSIDIndex)
                {	
					rfband = WlanList[index].X_HW_RFBand
					checkwlanInst = wlanInst;
					checkflag = 1;
                    if(true == IsAuthEAP(index))
					{
						extEnable = 1;
					}
                    break;
                }            
            }
        }
		
        setCheck('ExtendedWLC_' + wlanInst, extEnable);
			
		IsOnlyOneSsidExtEveryRFBandSupport(wificoverApId,checkflag,checkwlanInst,rfband);
				
        if (!IsBandCompatible(index, wificoverApId))
        {
            setDisable('ExtendedWLC_' + wlanInst, 1);
        }
    }    

    for (var i = 0; i < apNum; i++)
    {
        var ApInst = getInstIdByDomain(apDeviceList[i].domain);

        if (wificoverApId != ApInst)
        {
            continue;
        }
  
        curWorkMode = apDeviceList[i].WorkingMode; 

        break;
    }
}

var apDomain = "InternetGatewayDevice.X_HW_APDevice.1";
var wificoverApId = 1;
function setControl(ApInstId)
{
    wificoverApId = ApInstId;
    apDomain = "InternetGatewayDevice.X_HW_APDevice." + wificoverApId;
    SetApDetail(wificoverApId);
}

function ApplySubmit()
{
    var Form = new webSubmitForm();
    var setAction_AddExtWlc = '';
    var setAction_DelExtWlc = '';
    
    Form.addParameter('x.WorkingMode', curWorkMode);

    for (var i = 0; i < WlanListNum; i++)
    {
        var exsitFlag = 0;
        var wlanInst =  WlanList[i].WlanInst;
        var j = 0;
        var DelWlcInst = 0;

        for (j = 0; j < apExtendedWLC.length - 1; j++)
        {
            var path = "InternetGatewayDevice.X_HW_APDevice.";
            var ApInst = apExtendedWLC[j].domain.charAt(path.length);
            
            if (wificoverApId != ApInst)
            {
                continue;
            }

            if (wlanInst ==  apExtendedWLC[j].SSIDIndex)
            {
                DelWlcInst = getInstIdByDomain(apExtendedWLC[j].domain);

                exsitFlag = 1;
                break;
            }
        }

        if ( (1 == exsitFlag) && (0 == getCheckVal('ExtendedWLC_' + wlanInst)) )
        {
            var ExtWlcDomainDel = 'InternetGatewayDevice.X_HW_APDevice.' + wificoverApId + '.WifiCover.ExtendedWLC.' + DelWlcInst;
            setAction_DelExtWlc = setAction_DelExtWlc + '&Del_y_' + wlanInst + '=' + ExtWlcDomainDel;
        }

        if ( (0 == exsitFlag) && (1 == getCheckVal('ExtendedWLC_' + wlanInst)) )
        {
            Form.addParameter('Add_z_' + wlanInst + '.SSIDIndex', wlanInst);
            var ExtWlcDomainAdd = 'InternetGatewayDevice.X_HW_APDevice.' + wificoverApId + '.WifiCover.ExtendedWLC';
            setAction_AddExtWlc = setAction_AddExtWlc + '&Add_z_' + wlanInst + '=' + ExtWlcDomainAdd;
        }
    }

    Form.setAction('complex.cgi?x=' + apDomain + '.WifiCover'
									+ setAction_DelExtWlc
                                    + setAction_AddExtWlc
                                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');

    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
	setDisable('btnApplySubmit', 1);
}

function stIspSsid(domain, SSID_IDX)
{
    this.domain = domain;
    this.SSID_IDX = SSID_IDX;
}

var IspSsidList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.X_HW_WLANForISP.{i}, SSID_IDX, stIspSsid);%>;

function IsIspSsid(wlanInst)
{
    for (var i = 0; i < IspSsidList.length - 1; i++)
    {
        if (wlanInst == IspSsidList[i].SSID_IDX)
        {
            return true;        
        }
    }

    return false;
}

function cancelValue()
{

}

var FirstCfgApInst = 0;
function LoadFrame()
{ 
    LoadResource();

    setText('wifiCoverForceSwitch', WifiCoverService[0].ForcedSwitchThrehold);
    setText('wifiCoverConditionalSwitch', WifiCoverService[0].ConditionalSwitchThrehold); 
	
    if (0 == apNum)
    {
        setDisplay('divApDetailCfg', 0);
    }
    else
    {
        setDisplay('divApDetailCfg', 1);
    }

    selectLine('record_' + FirstCfgApInst);
}

function SyncWifiSwitch()
{
	var Form = new webSubmitForm();
	Form.addParameter('x.SyncWifiSwitch', getCheckVal('SyncWifiSwitch'));
    Form.setAction('set.cgi?'
                    + 'x=' + 'InternetGatewayDevice.X_HW_WifiCoverService'
                    + '&RequestFile=html/amp/wificovercfg/wifiCover.asp');
                    
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function IsAuthEAP(index)
{
	var beanconType = WlanList[index].BeaconType;
	var AuthMode;
	
	if('WPA' == beanconType)
	{
		AuthMode = WlanList[index].WPAAuthenticationMode;
	}
	
	if('WPA2' == beanconType || '11i' == beanconType)
	{
		AuthMode = WlanList[index].IEEE11iAuthenticationMode;
	}
	
	if('WPAand11i' == beanconType || 'WPA/WPA2' == beanconType)
	{
		AuthMode = WlanList[index].X_HW_WPAand11iAuthenticationMode;
	}
	
	if('EAPAuthentication' == AuthMode)
	{
		return false;
	}
	
	return true;
}

function setCheckDisable(id)
{
	var wlanInst = id.substring(id.length-1);
	var rfband = 0;
	var devicetype = apDeviceList[wificoverApId-1].DeviceType;	
	
	for(var j = 0;j < WlanListNum; j++)
	{
		if(wlanInst == getInstIdByDomain(WlanList[j].domain))
		{
			if(false == IsAuthEAP(j))
			{
				if(1 == getCheckVal('ExtendedWLC_' + wlanInst))
				{
					AlertEx(wificovercfg_language['amp_wificover_config_wlan_eap_auth']);
					setCheck('ExtendedWLC_' + wlanInst,0);
				}
			}
			rfband = WlanList[j].LowerLayers.substring(WlanList[j].LowerLayers.length-1);
		}
	}
	
	if(("Honor" == devicetype) || ("PT230" == devicetype))
	{	
		if('1' == rfband)
		{
			if (1 == getCheckVal(id))
			{
				for(var index = 0;index < WlanListNum; index++)
				{
					var wlanIndex = getInstIdByDomain(WlanList[index].domain);
					
					if (IsIspSsid(wlanIndex))
					{
						continue ;
					} 
                                    if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                                    {
                                        continue;
                                    }
					if(1 != WlanList[index].X_HW_ServiceEnable)
					{
						continue;
					}
					
					if (-1 != WlanList[index].X_HW_RFBand.indexOf("5G"))
					{
						continue;
					}  
					
					if(wlanIndex != wlanInst)
					{
						setDisable('ExtendedWLC_' + wlanIndex, 1);
					}
				}
			}
			else
			{
				for(var index = 0;index < WlanListNum; index++)
				{
					var wlanIndex = getInstIdByDomain(WlanList[index].domain);
					
					if (IsIspSsid(wlanIndex))
					{
						continue ;
					} 
                                    if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                                    {
                                        continue;
                                    }
					if(1 != WlanList[index].X_HW_ServiceEnable)
					{
						continue;
					}
					
					if (-1 != WlanList[index].X_HW_RFBand.indexOf("5G"))
					{
						continue;
					}  
					
					setDisable('ExtendedWLC_' + wlanIndex, 0);
				}
			}
		}
		
		if('2' == rfband)
		{
			if (1 == getCheckVal(id))
			{
				for(var index = 0;index < WlanListNum; index++)
				{
					var wlanIndex = getInstIdByDomain(WlanList[index].domain);
					
					if (IsIspSsid(wlanIndex))
					{
						continue ;
					} 
                                    if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                                    {
                                        continue;
                                    }
					if(1 != WlanList[index].X_HW_ServiceEnable)
					{
						continue;
					}
		
					if (-1 != WlanList[index].X_HW_RFBand.indexOf("2.4G"))
					{
						continue;
					}  
					
					if(wlanIndex != wlanInst)
					{
						setDisable('ExtendedWLC_' + wlanIndex, 1);
					}
				}
			}
			else
			{
				for(var index = 0;index < WlanListNum; index++)
				{
					var wlanIndex = getInstIdByDomain(WlanList[index].domain);
					
					if (IsIspSsid(wlanIndex))
					{
						continue ;
					} 
                                    if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                                    {
                                        continue;
                                    }
					if (-1 != WlanList[index].X_HW_RFBand.indexOf("2.4G"))
					{
						continue;
					}  

					setDisable('ExtendedWLC_' + wlanIndex, 0);
				}
			}
		}
	}
}

</script>

</head>

<body class="mainbody" onLoad="LoadFrame();" >
<table width="100%" height="5" border="0" cellpadding="0" cellspacing="0"><tr> <td></td></tr></table>  
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("WifiCoverCfg", GetDescFormArrayById(wificovercfg_language, "amp_wificover_config_header"), GetDescFormArrayById(wificovercfg_language, "amp_wificover_config_desc"), false);
</script>

<div class="title_spread"></div>

<table>
  <tr id="trUpnpEable" style="display:none"><td>
    <input type='checkbox' name='UpnpEnable' id='UpnpEnable' onClick='UpnpEnableSubmit();' value="ON">
      <script>
        setCheck('UpnpEnable', WifiCoverService[0].Enable);
        document.write(wificovercfg_language['amp_wificover_enable']); 
        if (true == UPNPCfgFlag) {getElById("trUpnpEable").style.display = "";}
	  </script>
    </input></td>
  </tr>
</table>

<div id='divWifiCoverCfgAll' style="display:none">

<div>
	<tr>
		<td>
			<input type="checkbox" name="SyncWifiSwitch" id="SyncWifiSwitch"  onclick="SyncWifiSwitch();" value="OFF"/>
		</td>
	<td>
	<script>
		document.write(wificovercfg_language['amp_wificover_config_wlan_enable_sync']);
	</script></td>
	<script>
		if(1 == WifiCoverService[0].SyncWifiSwitch)
		{
			setCheck('SyncWifiSwitch',1);
		}
		else
		{
			setCheck('SyncWifiSwitch',0);
		}
	</script>
	</tr>
</div>
<div class="title_spread"></div>
	<div>
		<script>   
	            document.write(wificovercfg_language['amp_wificover_config_autoenable']);
	    </script>
	</div>
	<table height="50" cellspacing="0" cellpadding="0" width="100%" border="0" class="tabal_01">		
		<tr class="tabal_01">
		<td>
		<input type="radio" name="AutoExtendedPolicy" id = "AutoExtendedPolicy" value = "1" onclick = "onClickSelectPolicy()" />
			<script> 
	            document.write(wificovercfg_language['amp_wificover_config_not_autosync']);
	        </script>
			</td>
		</tr >
		<tr class="tabal_01">
			<td >
				<input type="radio" name="AutoExtendedPolicy" id = "AutoExtendedPolicy" value = "2" onclick = "onClickSelectPolicy()" />
					<script>   
			            document.write(wificovercfg_language['amp_wificover_config_specify_autosync']);
			        </script>
			</td>
			<td class="tabal_01">
				<select name="CoverSsidSelect" id="Cover2GSsidSelect" onchange="funCover2GSsidSelect();">
			        <script >
					   var selectedflag = false;
			           for (var index = 0; index < WlanListNum; index++)
			           {						
							if(WlanList[index].LowerLayers.substring(WlanList[index].LowerLayers.length-1) == '1')
							{
							   var wlanInst = getInstIdByDomain(WlanList[index].domain);

								if (IsIspSsid(wlanInst))
								{
									continue;
								}  
								
								if(1 != WlanList[index].X_HW_ServiceEnable)
								{
									continue;
								}

                                                    if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                                                    {
                                                        continue;
                                                    }
				
							   if (wlanInst == ConfigurationByRadio[0].AutoExtendedSSIDIndex)
							   {
									selectedflag = true;
								   document.write('<option value='+ wlanInst +' selected>' + htmlencode(WlanList[index].ssid) + '(2.4G)' + '</option>');
							   }
							   else
							   {
								   document.write('<option value='+ wlanInst +'>' + htmlencode(WlanList[index].ssid) + '(2.4G)' + '</option>');
							   }
						   }
			           }
					   document.write('<option value='+ 0 +' ' + (selectedflag ? "" : "selected") + '  >' +'</option>');   
			       </script>
				</select>
			</td>	
			<td class="tabal_01">
				<select name="CoverSsidSelect" id="Cover5GSsidSelect" onchange="funCover5GSsidSelect();">
			        <script >
					   setDisplay('Cover5GSsidSelect',(1 == DoubleFreqFlag));
					   var selectedflag = false;
			           for (var index = 0; index < WlanListNum; index++)
			           {
					       if((WlanList[index].LowerLayers.substring(WlanList[index].LowerLayers.length-1) == '2'))
						   {
							   var wlanInst = getInstIdByDomain(WlanList[index].domain);

								if (IsIspSsid(wlanInst))
								{
									continue;
								}
                                
                                                        if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
                                                        {
                                                            continue;
                                                        }
                                                        
								if(1 != WlanList[index].X_HW_ServiceEnable)
								{
									continue;
								}
				
							  if (wlanInst == ConfigurationByRadio[1].AutoExtendedSSIDIndex)
							   {
								   selectedflag = true;
								   document.write('<option value='+ wlanInst +' selected>' + htmlencode(WlanList[index].ssid) + '(5G)' +'</option>');
							   }
							   else
							   {
								   document.write('<option value='+ wlanInst +'>' + htmlencode(WlanList[index].ssid) + '(5G)' +'</option>');
							   }
						   }
			           }
					   document.write('<option value='+ 0 +' ' + (selectedflag ? "" : "selected") + '  >' +'</option>');   
			       </script>
      			</select>
			</td>
		</tr>
		<tr class="tabal_01">
			<td>
				<input type="radio" name="AutoExtendedPolicy" id = "AutoExtendedPolicy" value = "3" onclick = "onClickSelectPolicy()" />
				<script>   
		            document.write(wificovercfg_language['amp_wificover_config_make_effort_sync']);
		        </script>
			</td>
				
		</tr>
		<script>
				if(0 == WifiCoverService[0].AutoExtended)
				{
					setRadio('AutoExtendedPolicy',1);
					setDisable('Cover2GSsidSelect',1);
					setDisable('Cover5GSsidSelect',1);
				}
				else if(WifiCoverService[0].AutoExtended && (WifiCoverService[0].AutoExtendedPolicy == 0))
				{
					setRadio('AutoExtendedPolicy',2);
				}
				else if(WifiCoverService[0].AutoExtended && WifiCoverService[0].AutoExtendedPolicy)
				{
					setRadio('AutoExtendedPolicy',3);
					setDisable('Cover2GSsidSelect',1);
					setDisable('Cover5GSsidSelect',1);
				}				
		</script>
	</table>

<div class="func_spread"></div>

<form id="WifiCoverSwitchForm">

<div id="wlanadv_head" class="func_title"><SCRIPT>document.write(wificovercfg_language["amp_wificover_fbt_title"]);</SCRIPT></div>

<table id="WifiCoverSwitchTbl" class="tabal_noborder_bg" width="100%" cellspacing="1" cellpadding="0"> 
<li  id="AutoSwitchAP" 			RealType="CheckBox"  	DescRef="amp_wificover_fbt_enable"      	 RemarkRef="Empty"     ErrorMsgRef="Empty"    Require="FALSE"    BindField="x.AutoSwitchAP"    InitValue="Empty"/>
<li  id="wifiCoverForceSwitch" 	RealType="TextBox"  	DescRef="amp_wifiCover_forceSwitch"     	 RemarkRef="amp_wifiCover_forceSwitchValues"  		ErrorMsgRef="Empty"    Require="FALSE"    BindField="x.ForcedSwitchThrehold" InitValue="Empty"/>
<li  id="wifiCoverConditionalSwitch" RealType="TextBox"  DescRef="amp_wifiCover_ConditionalSwitch"  	 RemarkRef="amp_wifiCover_ConditionalSwitchValues"  ErrorMsgRef="Empty"    Require="FALSE"    BindField="x.ConditionalSwitchThrehold" InitValue="Empty"/>
</table>

<script>
var TableClass = new stTableClass("width_per30", "width_per70", "", "StyleSelect");
HWParsePageControlByID("WifiCoverSwitchForm", TableClass ,wificovercfg_language, null);
setCheck('AutoSwitchAP', WifiCoverService[0].AutoSwitchAP);
</script>
<table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
  <tr >
    <td class="table_submit width_per25"></td>
    <td class="table_submit">
        <button id="applyButton" name="applyButton" type="button"  class="ApplyButtoncss buttonwidth_100px" onClick="wifiCoverAdvSubmit();">
            <script>document.write(wificovercfg_language['amp_wificover_config_apply']);</script></button>
        <button id="cancelButton" name="cancelButton" type="button" class="CancleButtonCss buttonwidth_100px" onClick="wifiCoverAdvCancel();">
            <script>document.write(wificovercfg_language['amp_wificover_config_cancel']);</script></button>
     </td>
   </tr>
</table>

</form>

<div class="func_spread"></div>

<form id="WifiCoverCfgForm" action="../network/set.cgi">

<div class="func_title"><SCRIPT>document.write(wificovercfg_language["amp_wificover_config_list_head"]);</SCRIPT></div>

<table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg">
  <tr  class="head_title"> 
    <td BindText='amp_wificover_config_index'></td>
    <td BindText='amp_wificover_config_devtype'></td>
    <td BindText='amp_wificover_onlineap_sn'></td>
    <td BindText='amp_wificover_config_status'></td>
    <td BindText='amp_wificover_config_onlinetime'></td>
    <td BindText='amp_wificover_config_status_desc'></td>
  </tr>
  <script language="JavaScript" type="text/JavaScript">
   var index = 0;
   
   FirstCfgApInst = 0;
   
   if (0 == apNum)
   {
            document.writeln("<tr class='tabal_01'>");
            document.writeln("<td class='align_center'>--</td>");        
            document.writeln("<td class='align_center'>--</td>");
            document.writeln("<td class='align_center'>--</td>");
            document.writeln("<td class='align_center'>--</td>");
            document.writeln("<td class='align_center'>--</td>");
            document.writeln("<td class='align_center'>--</td>");
            document.writeln("</tr>");
   }
   else
   {
        var CfgApNum = 0;
       for (index = 0; index < apNum; index++)
       {
            var ApInstId = getInstIdByDomain(apDeviceList[index].domain);
            
            CfgApNum++;
            if (1 == CfgApNum)
            {
                FirstCfgApInst = ApInstId;
            }

            if(index%2 == 0)
            {
                document.write('<tr id="record_' + ApInstId  + '" class="tabal_01" onclick="selectLine(this.id);">');
            }
            else
            {
                document.write('<tr id="record_' + ApInstId  + '" class="tabal_02" onclick="selectLine(this.id);">');
            }
            document.write('<td class=\"align_center\">'+ApInstId    +'</td>');
            document.write('<td class=\"align_center\">'+apDeviceList[index].DeviceType    +'</td>');
            document.write('<td class=\"align_center\">'+apDeviceList[index].SerialNumber    +'</td>');
            document.write('<td class=\"align_center\">'+apDeviceList[index].DeviceStatus    +'</td>');
            document.write('<td class=\"align_center\">'+apDeviceList[index].UpTime    +'</td>');

            getSyncStauts(apDeviceList[index].SyncStatus);
            document.write('<td class=\"align_center\">'+ syncstatus    +'</td>');

            document.write("</tr>");
       }
   }   
  </script>
</table>

<div id='divApDetailCfg'>

<div class="func_spread"></div>

<div class="func_title"><SCRIPT>document.write(wificovercfg_language["amp_wificover_config_detail_head"]);</SCRIPT></div>

<table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg" >
    <script language="JavaScript" type="text/JavaScript">
    var DoubelWlanFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';

    if (0 == DoubelWlanFlag)
    {
        document.write('<tr class="tabal_01" >');

        document.write('<td width="35%" >');
        document.write(wificovercfg_language['amp_wificover_config_extssidselect']);
        document.write('</td>');
        
        document.write('<td class="table_right" >');
        document.write("<ul style= 'list-style:none;padding-left:5px;margin-top:5px; margin-bottom:5px;'>");
        for (var index = 0; index < WlanListNum; index++)
        {
            var extEnable = 0;
            var wlanInst = getInstIdByDomain(WlanList[index].domain);
			
			var radio = (WlanList[index].LowerLayers.substring(WlanList[index].LowerLayers.length-1) == '1') ? '(2.4G)' : '(5G)';

            if (IsIspSsid(wlanInst))
            {
                continue;
            }
            if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
            {
                continue;
            }
			
			if(1 != WlanList[index].X_HW_ServiceEnable)
			{
				continue;
			} 
			
			document.write("<li>");

            document.write('<input type="checkbox" style = "margin-left:20px" id = "checkssid '+ wlanInst +'" name="ExtendedWLC_' + wlanInst + '" value="ExtendedWLC_' + wlanInst + '" onClick="setCheckDisable(this.id)">' + htmlencode(WlanList[index].ssid) +radio);
            for (var extWlcLoop = 0; extWlcLoop < apExtendedWLC.length - 1; extWlcLoop++)
            {
                if (wlanInst == apExtendedWLC[extWlcLoop].SSIDIndex)
                {
                    if(true == IsAuthEAP(index))
					{
						extEnable = 1;
					}
                    break;
                }
            }
            
            setCheck('ExtendedWLC_' + wlanInst, extEnable); 
			
			document.write("</li>");		
        }
        document.write("</ul>"); 
        document.write('</td>');
		document.write('</tr>');
    }
    else
    {
        document.write('<tr class="tabal_01">');
        
        document.write('<td width="35%" rowspan="2" >');
        document.write(wificovercfg_language['amp_wificover_config_extssidselect']);
        document.write('</td>');

		document.write('<td class="table_right" >');

        document.write("<ul style='list-style:none;padding-left:5px;margin-top:5px; margin-bottom:5px '>");
		
        for (var index = 0; index < WlanListNum; index++)
        {
            var wlanInst = getInstIdByDomain(WlanList[index].domain);
			var radio = (WlanList[index].LowerLayers.substring(WlanList[index].LowerLayers.length-1) == '1') ? '(2.4G)' : '(5G)';
			
            if (IsIspSsid(wlanInst))
            {
                continue;
            }
            if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
            {
                continue;
            }
			if(1 != WlanList[index].X_HW_ServiceEnable)
			{
				continue;
			}
            
            if (-1 != WlanList[index].X_HW_RFBand.indexOf("5G"))
            {
                continue;
            }     
			

			document.write("<li>");

            document.write('<input type="checkbox" id = "checkssid '+ wlanInst +'" style = "margin-left:20px" name="ExtendedWLC_' + wlanInst + '" value="ExtendedWLC_' + wlanInst + '" onClick="setCheckDisable(this.id)" >' + htmlencode(WlanList[index].ssid) + radio);
		
            for (var extWlcLoop = 0; extWlcLoop < apExtendedWLC.length - 1; extWlcLoop++)
            {
                if (wlanInst == apExtendedWLC[extWlcLoop].SSIDIndex)
                {
					if(true == IsAuthEAP(index))
					{
						extEnable = 1;
					}
                    break;
                }
            }
			
			setCheck('ExtendedWLC_' + wlanInst, extEnable);   
            
			document.write("</li>");
			
        }
        document.write("</ul>"); 
        document.write('</td>');
		document.write('</tr>');
            

 		document.write('<tr class="tabal_01">');
        document.write('<td class="table_right" >');

        document.write("<ul style= 'list-style:none;padding-left:5px;margin-top:5px; margin-bottom:5px'>");        
        for (var index = 0; index < WlanListNum; index++)
        {
            var wlanInst = getInstIdByDomain(WlanList[index].domain);
        	var radio = (WlanList[index].LowerLayers.substring(WlanList[index].LowerLayers.length-1) == '1') ? '(2.4G)' : '(5G)';
			
            if (IsIspSsid(wlanInst))
            {
                continue;
            }
            if ((wlanInst == fonssidinst.fonssid2g) || (wlanInst == fonssidinst.fonssid5g))
            {
                continue;
            }
			if(1 != WlanList[index].X_HW_ServiceEnable)
			{
				continue;
			}
			
            if (-1 != WlanList[index].X_HW_RFBand.indexOf("2.4G"))
            {
                continue;
            }
			
			document.write("<li>");
            document.write('<input type="checkbox" id = "checkssid '+ wlanInst +'" style = "margin-left:20px" name="ExtendedWLC_' + wlanInst + '" value="ExtendedWLC_' + wlanInst + '" onClick="setCheckDisable(this.id)" >' + htmlencode(WlanList[index].ssid) + radio);
			
            for (var extWlcLoop = 0; extWlcLoop < apExtendedWLC.length - 1; extWlcLoop++)
            {
                if (wlanInst == apExtendedWLC[extWlcLoop].SSIDIndex)
                {
                    if(true == IsAuthEAP(index))
					{
						extEnable = 1;
					}
                    break;
                }
            }
            
            setCheck('ExtendedWLC_' + wlanInst, extEnable);
			
			
			document.write("</li>");
        }  
        document.write("</ul >");  
        document.write('</td>');
        document.write('</tr>');
    }
    </script>
</table>

<table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
  <tr >
    <td class="table_submit width_per25"></td>
    <td class="table_submit">
      <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
      <button id="btnApplySubmit" name="btnApplySubmit" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="ApplySubmit();"><script>document.write(wificovercfg_language['amp_wificover_config_apply']);</script></button>
      <button id="cancel" name="cancel" type="button" class="CancleButtonCss buttonwidth_100px" onClick="cancelValue();"><script>document.write(wificovercfg_language['amp_wificover_config_cancel']);</script></button>
     </td>
   </tr>
</table>
</div>

</form>

</div>

<script>
if (true == UPNPCfgFlag)
{
    setDisplay('divWifiCoverCfgAll', getCheckVal('UpnpEnable'));
}
else
{
    setDisplay('divWifiCoverCfgAll', 1);
}
</script>

</body>
</html>
