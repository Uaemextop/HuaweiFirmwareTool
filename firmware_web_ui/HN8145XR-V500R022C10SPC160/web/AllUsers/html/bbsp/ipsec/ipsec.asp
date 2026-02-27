<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>

<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../../bbsp/common/wan_list_info.asp"></script>
<script language="javascript" src="../../bbsp/common/wan_list.asp"></script>
<title>IPSec</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(errdes.html);%>"></script>

<style>
.width_150px {
    width: 150px;
}
</style>

<script language="JavaScript" type="text/javascript">
var LoginRequestLanguage = '<%HW_WEB_GetLoginRequestLangue();%>';
var PublicIpFlag = '<%HW_WEB_GetFeatureSupport(BBSP_FT_SNAT_IPMAPPING);%>';
var curUserType='<%HW_WEB_GetUserType();%>';
var sysUserType = '0';
var curCfgModeWord ='<%HW_WEB_GetCfgMode();%>';
var WanIndex = -1;
var appName = navigator.appName;
var realConstSrvName='constsrvName';

var numpara = "";
if(window.location.href.indexOf("?") > 0) {
    numpara = window.location.href.split("?")[1];
}

function filterWan(WanItem) {
    if (((WanItem.Tr069Flag == '0') && (Instance_IspWlan.IsWanHidden(domainTowanname(WanItem.domain)) == false)) == false) {
        return false;
    }

    return true;
}

var WanInfo = GetWanListByFilter(filterWan);
var MASK = '********************************';
function stIpSecVPN(domain,Enable,IPSecType,RemoteSubnet,LocalSubnet,IPSecEncapsulationMode,IPSecOutInterface,RemoteIP,RemoteDomain,ExchangeMode,IKEAuthenticationMethod,IKEAuthenticationAlgorithm,IKEEncryptionAlgorithm,IKEDHGroup,IKEIDType,IKELocalName,IKERemoteName,IPSecTransform,ESPAuthenticationAlgorithm,ESPEncryptionAlgorithm,IPSecPFS,AHAuthenticationAlgorithm,IKESAPeriod,IPSecSATimePeriod,IPSecSATrafficPeriod,DPDEnable,DPDThreshold,DPDRetry,X_HW_IKEVersion,ConnectionStatus,AddressPool,IKECertificate) {
    this.domain = domain;
    this.Enable = Enable;
    this.IPSecType = IPSecType;
    this.RemoteSubnet = RemoteSubnet;
    this.LocalSubnet = LocalSubnet;
    this.IPSecEncapsulationMode = IPSecEncapsulationMode;
    this.IPSecOutInterface= IPSecOutInterface;
    this.RemoteIP = RemoteIP;
    this.RemoteDomain = RemoteDomain;
    this.ExchangeMode = ExchangeMode;
    this.IKEAuthenticationMethod = IKEAuthenticationMethod;
    this.IKEAuthenticationAlgorithm = IKEAuthenticationAlgorithm;
    this.IKEEncryptionAlgorithm = IKEEncryptionAlgorithm;
    this.IKEDHGroup = IKEDHGroup;
    this.IKEIDType = IKEIDType;
    this.IKELocalName = IKELocalName;
    this.IKEPreshareKey = MASK;
    this.IKERemoteName = IKERemoteName;
    this.IPSecTransform = IPSecTransform;
    this.ESPAuthenticationAlgorithm = ESPAuthenticationAlgorithm;
    this.ESPEncryptionAlgorithm = ESPEncryptionAlgorithm;
    this.IPSecPFS = IPSecPFS;
    this.AHAuthenticationAlgorithm = AHAuthenticationAlgorithm;
    this.IKESAPeriod = IKESAPeriod;
    this.IPSecSATimePeriod = IPSecSATimePeriod;
    this.IPSecSATrafficPeriod = IPSecSATrafficPeriod;
    this.DPDEnable = DPDEnable;
    this.DPDThreshold = DPDThreshold;
    this.DPDRetry = DPDRetry;
    this.X_HW_IKEVersion = X_HW_IKEVersion;
    this.ConnectionStatus = ConnectionStatus;
    this.AddressPool = AddressPool;
    this.IKECertificate = IKECertificate;
    var index = domain.lastIndexOf('A8C_IPSecVPN');
    this.Interface = domain.substr(0,index - 1);
}

function stAdressConfig(domain,MinAddress,MaxAddress,SubnetMask,DNSServer) {
    this.domain = domain;
    this.MinAddress = MinAddress;
    this.MaxAddress = MaxAddress;
    this.SubnetMask = SubnetMask;
    this.DNSServer = DNSServer;
}

var IPSecVPN = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.A8C_IPSecVPN.{i},Enable|IPSecType|RemoteSubnet|LocalSubnet|IPSecEncapsulationMode|IPSecOutInterface|RemoteIP|RemoteDomain|ExchangeMode|IKEAuthenticationMethod|IKEAuthenticationAlgorithm|IKEEncryptionAlgorithm|IKEDHGroup|IKEIDType|IKELocalName|IKERemoteName|IPSecTransform|ESPAuthenticationAlgorithm|ESPEncryptionAlgorithm|IPSecPFS|AHAuthenticationAlgorithm|IKESAPeriod|IPSecSATimePeriod|IPSecSATrafficPeriod|DPDEnable|DPDThreshold|DPDRetry|X_HW_IKEVersion|ConnectionStatus|AddressPool|IKECertificate,stIpSecVPN);%>;

var VPN_VPNConfig = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.AddressPool.{i},MinAddress|MaxAddress|SubnetMask|DNSServer, stAdressConfig);%>;

var VPNConfigNum = 0;
var VPNConfigInst = new Array();

for (var i = 0; i < VPN_VPNConfig.length - 1; i++) {
    VPNConfigInst[VPNConfigNum++] = VPN_VPNConfig[i];
}

function CertificateInfo(domain, X_HW_Usage, X_HW_Thumbprint) {
    this.domain = domain;
    this.usage = X_HW_Usage;
    this.thumbprint = X_HW_Thumbprint;
}
var certificateList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DataModel.Security.Certificate.{i}, X_HW_Usage|X_HW_Thumbprint, CertificateInfo);%>;
var ipsecCertInfoList = new Array();
for (var i = 0; i < certificateList.length - 1; i++) {
    if (certificateList[i].usage == 'ONT_AUTHEN_IPSEC') {
        ipsecCertInfoList.push(certificateList[i]);
    }
}

function loadlanguage()
{
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length ; i++) {
        var b = all[i];
        if(b.getAttribute("BindText") == null) {
            continue;
        }
        b.innerHTML = ipsec_language[b.getAttribute("BindText")];
    }
}

var IPSec = new Array();
var Idx = 0;
var AddFlag = true;
var selctIndex = -1;
var poolIndex = -1;
var ipsecAddressPool = '';
var cnt = '';
var errFlag = 0;

function GetLanguageDesc(errcode) {
    return ipsec_language[errcode];
}

function ipsecShowResult(Result) {
    var errorCodeArray = new Array('0xf7376001','0xf7376002', '0xf7376003', '0xf7376004', '0xf7376005', '0xf7376006', '0xf7376007');
    var errorstring = new Array('ipsec_0x01', 'ipsec_0x02', 'ipsec_0x03', 'ipsec_0x04', 'ipsec_0x05', 'ipsec_0x06', 'ipsec_0x07');
    try {
        var ResultInfo = JSON.parse(hexDecode(Result));
        if (0 == ResultInfo.result) {
            return;
        }
        
        for (i = 0; i < errorCodeArray.length; i++) {
            if (errorCodeArray[i] == ResultInfo.error) {
                errFlag = 1;
                AlertEx(GetLanguageDesc(errorstring[i]));
                return;
            }
        }

        var errData = errLanguage['s' + ResultInfo.error];
        if ('string' != typeof(errData)) {
            errData = errLanguage['s0xf7205001'];
        }
        errFlag = 1;
        AlertEx(errData);
    } catch(e){
        errData = errLanguage['s0xf7205001'];
        errFlag = 1;
        AlertEx(errData);
    }
    return;
}

function addIpsecAddressPool(addParameter) {
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        data : addParameter + '&x.X_HW_Token='+ getValue('onttoken'),
        url :  'addajax.cgi?y=InternetGatewayDevice.X_HW_VPN.AddressPool' + '&RequestFile=/html/bbsp/ipsec/ipsec.asp',
        success : function(data) {
            ipsecShowResult(data);
            cnt = 'success';
        },
        error:function(XMLHttpRequest, textStatus, errorThrown) {
            if(XMLHttpRequest.status == 404) {
            }
        }
    });
}

function setNodeAttr() {
    var isPoolEnable = getCheckVal('pool_enable');
    var minAddress = getValue('vpn_min_address');
    var maxAddress = getValue('vpn_max_address');
    var subnetMask = getValue('vpn_subnet_mask');
    var dnsServer = getValue('vpn_DNS_server');
    var addParameter = 'y.MinAddress=' + minAddress + '&y.MaxAddress=' + maxAddress + '&y.SubnetMask=' + subnetMask + '&y.DNSServer=' + dnsServer;

    if(ipsecAddressPool) {
        var pindex = ipsecAddressPool.lastIndexOf('.');
        poolIndex  = ipsecAddressPool.substring(pindex + 1, ipsecAddressPool.length);
    }

    if (AddFlag == true) {
        if (isPoolEnable == '1') {
            if (VPN_VPNConfig.length > 8) {
                AlertEx(ipsec_language['ipsec_s083']);
                return false;
            }
            addIpsecAddressPool(addParameter);
        }
    } else {
        if (isPoolEnable == '1') {
            if (poolIndex == -1) {
                if (VPN_VPNConfig.length > 8) {
                    AlertEx(ipsec_language['ipsec_s083']);
                    return false;
                }
                addIpsecAddressPool(addParameter);
            } else {
                $.ajax({
                    type : "POST",
                    async : false,
                    cache : false,
                    data : 'y.MinAddress=' + minAddress + '&y.MaxAddress=' + maxAddress + '&y.SubnetMask=' + subnetMask + '&y.DNSServer=' + dnsServer + '&x.X_HW_Token=' + getValue('onttoken'),
                    url :  'setajax.cgi?y=' + ipsecAddressPool + '&RequestFile=/html/bbsp/ipsec/ipsec.asp',
                    success : function(data) {
                        ipsecShowResult(data);
                    },
                    error:function(XMLHttpRequest, textStatus, errorThrown) {
                        if(XMLHttpRequest.status == 404) {
                        }
                    }
                });
            }
        }
    }
    
    return true;
}

function AjaxdelIpsecDomain(pooldomain) {
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        data : pooldomain + "=" + '&x.X_HW_Token=' + getValue('onttoken'),
        url :  'del.cgi?' + '&RequestFile=/html/bbsp/ipsec/ipsec.asp',
        error:function(XMLHttpRequest, textStatus, errorThrown) {
            if(XMLHttpRequest.status == 404) {
            }
        }
    });
}

function GetVPNPoolInfo() {
    var tmp = '';
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        url : "/html/bbsp/ipsec/GetVPNPoolInfo.asp",
        success : function(data) {
            tmp = dealDataWithFun(data);
        }
    });
    return tmp;
}

function getAddressPoolDomain() {
    var vpnPoolList = '';
    var addressPoolDomain = '';

    if (setNodeAttr() == true) {
        vpnPoolList = GetVPNPoolInfo();

        if (cnt == 'success' && vpnPoolList.length > 1) {
            addressPoolDomain = vpnPoolList[vpnPoolList.length - 2].domain;
            cnt = '';
        }
        return addressPoolDomain;
    }
}

function Submit(type) {
    if (CheckForm(type) == true) {
        AddSubmitParam();
        DisableRepeatSubmit();
    }
}

function HwAjaxConfigPara(ObjPath, ParameterList, action) {
    $.ajax({
        type : "POST",
        async : true,
        cache : false,
        data : ParameterList + '&x.X_HW_Token='+ getValue('onttoken'),
        url :  action + '.cgi?x=' + ObjPath + "&RequestFile=html/bbsp/ipsec/ipsec.asp",
        error:function(XMLHttpRequest, textStatus, errorThrown) {
            if(XMLHttpRequest.status == 404) {
            }
        }
    });
}

function AddSubmitParam() {
    var ParameterList = "";
    var Interface = getSelectVal('WANselect_select');
    var url;
    var sndIKESAPeriod;
    var sndIPSecSATimePeriod;
    var sndIPSecSATrafficPeriod;
    var sndDPDThreshold;
    var sndDPDRetry;

    if(removeSpaceTrim(getValue('IKESAPeriod').toString()) == "") {
        sndIKESAPeriod = 10800;
    } else {
        sndIKESAPeriod = parseInt(getValue('IKESAPeriod'),10);
    }

    if(removeSpaceTrim(getValue('IPSecSATimePeriod').toString()) == "") {
        sndIPSecSATimePeriod = 3600;
    } else {
        sndIPSecSATimePeriod = parseInt(getValue('IPSecSATimePeriod'),10);
    }

    if(removeSpaceTrim(getValue('IPSecSATrafficPeriod').toString()) == "") {
        sndIPSecSATrafficPeriod = 1843200;
    } else {
        sndIPSecSATrafficPeriod = parseInt(getValue('IPSecSATrafficPeriod'),10);
    }

    if(removeSpaceTrim(getValue('DPDThreshold').toString()) == "") {
        sndDPDThreshold = 10;
    } else {
        sndDPDThreshold = parseInt(getValue('DPDThreshold'),10);
    }

    if(removeSpaceTrim(getValue('DPDRetry').toString()) == "") {
        sndDPDRetry = 5;
    } else {
        sndDPDRetry = parseInt(getValue('DPDRetry'),10);
    }

    var Enable = getCheckVal('Enable');
    var LocalSubnet = getValue('LocalSubnet');
    var RemoteSubnet = getValue('RemoteSubnet');
    var IPSecType_select = getSelectVal('IPSecType_select');
    var IPSecEncapsulationMode_select = getSelectVal('IPSecEncapsulationMode_select')
    var RemoteIP = getValue('RemoteIP');
    var RemoteDomain = getValue('RemoteDomain');

    ParameterList += 'x.Enable='+ Enable + '&x.LocalSubnet=' + LocalSubnet + '&x.RemoteSubnet=' + RemoteSubnet +
                     '&x.IPSecType=' + IPSecType_select + '&x.IPSecEncapsulationMode=' + IPSecEncapsulationMode_select;

    if (getSelectVal('WANselect_select') != 'None') {
        ParameterList += '&x.IPSecOutInterface=' + Interface;
    }

    if (getSelectVal('IPSecType_select') == 'Site-to-Site') {
        if (getRadioVal('idRadioDirectory') == '1') {
            ParameterList += '&x.RemoteIP=' + RemoteIP + '&x.RemoteDomain=';
        }
        else {
            ParameterList += '&x.RemoteIP=&x.RemoteDomain=' + RemoteDomain;
        }
    }

    var X_HW_IKEVersion = getSelectVal('X_HW_IKEVersion_select');
    var ExchangeMode = getSelectVal('ExchangeMode_select');
    var IKEAuthenticationMethod = getSelectVal('IKEAuthenticationMethod_select');
    var IKEAuthenticationAlgorithm = getSelectVal('IKEAuthenticationAlgorithm_select');
    var IKEEncryptionAlgorithm = getSelectVal('IKEEncryptionAlgorithm_select');
    var IKEDHGroup = getSelectVal('IKEDHGroup_select');
    var IKEIDType = getSelectVal('IKEIDType_select');
    var IKELocalName = getValue('IKELocalName');
    var preShardKey = getValue('IKEPreshareKey');
    var IKEPreshareKey = FormatUrlEncode(preShardKey);

    ParameterList += '&x.X_HW_IKEVersion=' + X_HW_IKEVersion + '&x.ExchangeMode=' + ExchangeMode + '&x.IKEAuthenticationMethod=' +
                     IKEAuthenticationMethod + '&x.IKEAuthenticationAlgorithm=' + IKEAuthenticationAlgorithm +
                     '&x.IKEEncryptionAlgorithm=' + IKEEncryptionAlgorithm + '&x.IKEDHGroup=' + IKEDHGroup + '&x.IKEIDType=' +
                     IKEIDType + '&x.IKELocalName=' + IKELocalName;

    if (preShardKey != '' && preShardKey != MASK && getSelectVal('IKEAuthenticationMethod_select') == 'PreShareKey') {
        ParameterList += '&x.IKEPreshareKey=' + IKEPreshareKey;
    }
    if ((getSelectVal('ChooseCert_select') != '') && (IKEAuthenticationMethod == 'RsaSignature')) {
        ParameterList += '&x.IKECertificate=' + getSelectVal('ChooseCert_select');
    }

    var IKERemoteName = getValue('IKERemoteName')
    var IPSecTransform = getSelectVal('IPSecTransform_select')
    var ESPAuthenticationAlgorithm = getSelectVal('ESPAuthenticationAlgorithm_select')
    var ESPEncryptionAlgorithm = getSelectVal('ESPEncryptionAlgorithm_select')
    var IPSecPFS = getSelectVal('IPSecPFS_select')
    var AHAuthenticationAlgorithm = getSelectVal('AHAuthenticationAlgorithm_select')
    var DPDEnable = getCheckVal('DPDEnable')

    ParameterList += '&x.IKERemoteName=' + IKERemoteName + '&x.IPSecTransform=' + IPSecTransform + '&x.ESPAuthenticationAlgorithm=' +
                     ESPAuthenticationAlgorithm + '&x.ESPEncryptionAlgorithm=' +ESPEncryptionAlgorithm + '&x.IPSecPFS=' + IPSecPFS +
                     '&x.AHAuthenticationAlgorithm=' + AHAuthenticationAlgorithm + '&x.IKESAPeriod=' + sndIKESAPeriod +
                     '&x.IPSecSATimePeriod=' + sndIPSecSATimePeriod+ '&x.IPSecSATrafficPeriod=' + sndIPSecSATrafficPeriod +
                     '&x.DPDEnable=' + DPDEnable + '&x.DPDThreshold=' + sndDPDThreshold + '&x.DPDRetry=' + sndDPDRetry;

    var addresspool = getAddressPoolDomain();

    if (errFlag == 1) {
        errFlag = 0;
        return false;
    }

    var isPoolEnable = getCheckVal('pool_enable');
    var ObjPath1 = 'InternetGatewayDevice.X_HW_VPN.A8C_IPSecVPN';
    var addAction = 'addcfg';
    var complexAction = 'complex';

    if (AddFlag == true) {
        if (isPoolEnable == '1') {
            if (!addresspool) {
                return false;
            }
            
            ParameterList += '&x.AddressPool=' + addresspool;
            HwAjaxConfigPara(ObjPath1, ParameterList, addAction);
        } else {
            HwAjaxConfigPara(ObjPath1, ParameterList, addAction);
        }
    } else {
        var ObjPath2 = IPSecVPN[selctIndex].domain;
        if (isPoolEnable == '1') {
            if (poolIndex == '-1') {
                if (!addresspool) {
                    return false;
                }
                ParameterList += '&x.AddressPool=' + addresspool;
                HwAjaxConfigPara(ObjPath2, ParameterList, complexAction);
            } else {
                HwAjaxConfigPara(ObjPath2, ParameterList, complexAction);
            }
        } else {
            if (poolIndex != '-1') {
                ParameterList += '&x.AddressPool=';
                HwAjaxConfigPara(ObjPath2, ParameterList, complexAction);
                AjaxdelIpsecDomain(ipsecAddressPool);
            } else {
                HwAjaxConfigPara(ObjPath2, ParameterList, complexAction);
            }
        }
    }
    setDisable('btnApply_ex',1);
    setDisable('cancelValue',1);
    setDisable('Add_button',1);
    setDisable('Del_button',1);
    window.location.href='/html/bbsp/ipsec/ipsec.asp';
}

function isValidIPWithMask(value) {
    var addrParts = value.split('/');
    var num = 0;
    if ((addrParts.length != 2) || (isAbcIpAddress(addrParts[0])) == false) {
        return false;
    }
    if (addrParts.length == 2) {
        if ((isInteger(addrParts[1]) == false) || (addrParts[1] < 1) || (addrParts[1] > 32)) {
            return false;
        }
    }
    return true;
}

function CheckIPSec() {
    with (getElById('IPSecForm')) {
        var localSubnetList = new Array();
        var remoteSubnetList = new Array();
        
        if (getValue('LocalSubnet') != "") {
            localSubnetList = getValue('LocalSubnet').split(',');
            for (var i = 0; i < localSubnetList.length; i++) {
                if (isValidIPWithMask(localSubnetList[i]) == false) {
                    AlertEx(ipsec_language['ipsec_s085'] + localSubnetList[i] + ipsec_language['ipsec_s086']);
                    return false;
                }
            }
            if (localSubnetList.length > 3) {
                AlertEx(ipsec_language['ipsec_s084']);
                return false;
            }
        }
        
        if (getValue('RemoteSubnet') != "") {
            remoteSubnetList = getValue('RemoteSubnet').split(',');
            for (var i = 0; i < remoteSubnetList.length; i++) {
                if (isValidIPWithMask(remoteSubnetList[i]) == false) {
                    AlertEx(ipsec_language['ipsec_s087'] + remoteSubnetList[i] + ipsec_language['ipsec_s086']);
                    return false;
                }

                if (localSubnetList.indexOf(remoteSubnetList[i]) > -1) {
                    AlertEx(ipsec_language['ipsec_s087'] + remoteSubnetList[i] + ipsec_language['ipsec_s088']);
                    return false;
                }
            }
            if (remoteSubnetList.length > 3) {
                AlertEx(ipsec_language['ipsec_s089']);
                return false;
            }
        }

        if (getSelectVal('IPSecType_select') == 'Site-to-Site') {
            if (getValue('LocalSubnet') == "") {
                AlertEx(ipsec_language['ipsec_s090']);
                return false;
            }
            if (getValue('RemoteSubnet') == "") {
                AlertEx(ipsec_language['ipsec_s091']);
                return false;
            }

            if (getRadioVal('idRadioDirectory') == '1') {
                if (getValue('RemoteIP') == "") {
                    AlertEx(ipsec_language['ipsec_s092']);
                    return false;
                } else if (getValue('RemoteIP') != ""  && isAbcIpAddress(getValue('RemoteIP')) == false) {
                    AlertEx(ipsec_language['ipsec_s093'] + getValue('RemoteIP') + ipsec_language['ipsec_s086']);
                    return false;
                }
            } else {
                if (getValue('RemoteDomain') == "") {
                    AlertEx(ipsec_language['ipsec_s094']);
                    return false;
                }
            }
        } else if (getSelectVal('IPSecType_select') == 'PC-to-Site') {
            if (getValue('LocalSubnet') == "") {
                AlertEx(ipsec_language['ipsec_s090']);
                return false;
            }
        }
        
        if (getSelectVal('IKEAuthenticationMethod_select') == 'PreShareKey') {
            if (getValue('IKEPreshareKey') == "") {
                AlertEx(ipsec_language['ipsec_s095']);
                return false;
            } else if (getValue('IKEPreshareKey') != "") {
                if ((getValue('IKEPreshareKey').toString().length < 8) || (getValue('IKEPreshareKey').toString().length > 128)) {
                    AlertEx(ipsec_language['ipsec_s096']);
                    return false;
                }
            }
        }

        if (getSelectVal('IKEIDType_select') == 'Name') {
            if (getValue('IKELocalName') == "") {
                AlertEx(ipsec_language['ipsec_s097']);
                return false;
            }
            if (getValue('IKERemoteName') == "") {
                AlertEx(ipsec_language['ipsec_s098']);
                return false;
            }
        }

        if ((getValue('ESPAuthenticationAlgorithm_select') == "None") && (getValue('ESPEncryptionAlgorithm_select') == "None")) {
            if (confirm(ipsec_language['ipsec_s099']) == false) {
                return false;
            }
        }
        
        if (CheckNumber(getValue('IKESAPeriod'), 1200, 86400) == false) {
             AlertEx(ipsec_language['ipsec_s100']);
             return false;
        }

        if (CheckNumber(getValue('IPSecSATimePeriod'), 600, 86400) == false) {
             AlertEx(ipsec_language['ipsec_s101']);
             return false;
        }
        
        if (CheckNumber(getValue('IPSecSATrafficPeriod'), 2560, 536870912) == false) {
             AlertEx(ipsec_language['ipsec_s102']);
             return false;
        }
        
        if (CheckNumber(getValue('DPDThreshold'), 10, 3600) == false) {
             AlertEx(ipsec_language['ipsec_s103']);
             return false;
        }
        
        if (CheckNumber(getValue('DPDRetry'), 2, 100) == false) {
             AlertEx(ipsec_language['ipsec_s104']);
             return false;
        }

        var poolEnable = getCheckVal('pool_enable');
        var minAddress = getValue("vpn_min_address");
        var maxAddress = getValue("vpn_max_address");
        var subnetMask = getValue("vpn_subnet_mask");
        var dnsServer = getValue("vpn_DNS_server");

        if (poolEnable == '1') {
            if (minAddress == "") {
                AlertEx(ipsec_language['ipsec_s105']);
                return false;
            } else if ((isAbcIpAddress(minAddress) == false) || (isDeIpAddress(minAddress) == true) ||
                       (isBroadcastIpAddress(minAddress) == true) || (isLoopIpAddress(minAddress) == true)) {
                AlertEx(ipsec_language['ipsec_s106'] + minAddress + ipsec_language['ipsec_s086']);
                return false;
            } else {
            }

            if (maxAddress == "") {
                AlertEx(ipsec_language['ipsec_s107']);
                return false;
            } else if ((isAbcIpAddress(maxAddress) == false) || (isDeIpAddress(maxAddress) == true) ||
                       (isBroadcastIpAddress(maxAddress) == true) || (isLoopIpAddress(maxAddress) == true)) {
                AlertEx(ipsec_language['ipsec_s108'] + maxAddress + ipsec_language['ipsec_s086']);
                return false;
            } else {
            }

            if ((subnetMask != "") && (isValidSubnetMask(subnetMask) == false)) {
                AlertEx(ipsec_language['ipsec_s109'] + subnetMask + ipsec_language['ipsec_s086']);
                return false;
            }

            if((dnsServer != "") && (isAbcIpAddress(dnsServer) == false) || (isDeIpAddress(dnsServer) == true) ||
               (isBroadcastIpAddress(dnsServer) == true) || (isLoopIpAddress(dnsServer) == true)) {
                AlertEx(ipsec_language['ipsec_s110'] + dnsServer + ipsec_language['ipsec_s086']);
                return false;
            }
        }
    }
    return true;
}

function CheckForm(type)
{
    switch (type) {
       case 3:
          return CheckIPSec();
          break;
    }

    return true;
}

function LoadFrame()
{
    setDisplay('Newbutton',0);
    setDisplay('DeleteButton',0);

    if (IPSecVPN.length > 1) {
        selectLine('record_0');
        setDisplay('ConfigForm',1);
    } else {
        selectLine('record_no');
        setDisplay('ConfigForm',0);
    }

    if(isValidIpAddress(numpara) == true) {
        clickAdd('IPsec');
        setText('InternalClient_text', numpara);
    }
    loadlanguage();
}

function getVirtualServerId(tableID,colID)
{
    var VirtualServerListId = "VirtualServer_" + tableID + "_" + colID + "_table";
    return VirtualServerListId;
}

function ShowIPSec()
{
    var html = '' ;
    var i = 0;
    var showEnable = '';
    var showIPSecEncapsulationMode = '';
    var showIPSecType = '';
    var showRemoteIP = '';
    for (i = 0; i < IPSecVPN.length - 1; i++) {
        var tableID = i + 2;
        html += '<TR id=record_' + i 
                +' class="tabal_01 align_center" onclick="record_click(this.id);">';
        if (IPSecVPN[i].Enable == '1')
            showEnable = ipsec_language['ipsec_s111'];
        else
            showEnable = ipsec_language['ipsec_s112'];
        if (IPSecVPN[i].IPSecEncapsulationMode == 'Transport')
            showIPSecEncapsulationMode = ipsec_language['ipsec_s018'];
        else if (IPSecVPN[i].IPSecEncapsulationMode == 'Tunnel')
            showIPSecEncapsulationMode = ipsec_language['ipsec_s017'];
        if (IPSecVPN[i].IPSecType == 'Site-to-Site')
            showIPSecType = ipsec_language['ipsec_s010'];
        else if (IPSecVPN[i].IPSecType == 'PC-to-Site')
            showIPSecType = ipsec_language['ipsec_s011'];
        
        if (IPSecVPN[i].RemoteDomain != '') {
            showRemoteIP = IPSecVPN[i].RemoteDomain
        } else if (IPSecVPN[i].RemoteIP != '') {
            showRemoteIP = IPSecVPN[i].RemoteIP
        } else {
            showRemoteIP = '';
        }

        if (IPSecVPN[i].IPSecType == 'PC-to-Site') {
            showRemoteIP = '--';
        }

        html +=  '<TD id=' + getVirtualServerId(tableID,1) + '>' + showEnable + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,2) + '>' + showRemoteIP + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,3) + '>' + showIPSecType + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,4) + '>' + showIPSecEncapsulationMode + '</TD>';
        html += '<TD ><input id=' + getVirtualServerId(tableID,5) + ' + type="checkbox" name=' + 
                getVirtualServerId(tableID,5) + ' + value="True"></TD>';
        html += '</TR>';
    }
    document.write(html);
}

function record_click(id)
{
    selectLine(id);
    setDisplay("typeTR",0);
}

function setCtlDisplay(record, vpnrecord)
{
    var endIndex = record.domain.lastIndexOf('IPSec') - 1;
    var Interface = record.domain.substring(0,endIndex);

    setCheck('Enable',record.Enable);
    setText('LocalSubnet',record.LocalSubnet);
    setText('RemoteSubnet',record.RemoteSubnet);
    setSelect('IPSecType_select',record.IPSecType);
    setSelect('IPSecEncapsulationMode_select',record.IPSecEncapsulationMode);

    if (record.IPSecOutInterface== '') {
        setSelect('WANselect_select','None');
    } else {
        setSelect('WANselect_select',record.IPSecOutInterface);
    }

    setRadio('idRadioDirectory', (record.RemoteDomain.length > 0 ? 0 : 1));
    setText('RemoteIP',record.RemoteIP);
    setText('RemoteDomain',record.RemoteDomain);
    setSelect('X_HW_IKEVersion_select',record.X_HW_IKEVersion);
    setSelect('ExchangeMode_select',record.ExchangeMode);
    setSelect('IKEAuthenticationMethod_select',record.IKEAuthenticationMethod);
    setText('IKEPreshareKey',record.IKEPreshareKey);
    setSelect('IKEAuthenticationAlgorithm_select',record.IKEAuthenticationAlgorithm);
    setSelect('IKEEncryptionAlgorithm_select',record.IKEEncryptionAlgorithm);
    setSelect('IKEDHGroup_select',record.IKEDHGroup);
    setSelect('IKEIDType_select',record.IKEIDType);
    setText('IKELocalName',record.IKELocalName);
    setText('IKERemoteName',record.IKERemoteName);
    setSelect('IPSecTransform_select',record.IPSecTransform);
    setSelect('ESPAuthenticationAlgorithm_select',record.ESPAuthenticationAlgorithm);
    setSelect('ESPEncryptionAlgorithm_select',record.ESPEncryptionAlgorithm);
    setSelect('IPSecPFS_select',record.IPSecPFS);
    setSelect('AHAuthenticationAlgorithm_select',record.AHAuthenticationAlgorithm);
    setText('IKESAPeriod',record.IKESAPeriod);
    setText('IPSecSATimePeriod',record.IPSecSATimePeriod);
    setText('IPSecSATrafficPeriod',record.IPSecSATrafficPeriod);
    setText('IPSecVPNAddressPool',record.IPSecVPNAddressPool);
    setCheck('DPDEnable',record.DPDEnable);
    setText('DPDThreshold',record.DPDThreshold);
    setText('DPDRetry',record.DPDRetry);
    setSelect('ChooseCert_select', record.IKECertificate);

    if (vpnrecord && selctIndex != -1) {
        setCheck('pool_enable', 1);
        setText('vpn_min_address',vpnrecord.MinAddress);
        setText('vpn_max_address',vpnrecord.MaxAddress);
        setText('vpn_subnet_mask',vpnrecord.SubnetMask);
        setText('vpn_DNS_server',vpnrecord.DNSServer);
        
        SetIpsecAddress();
    } else {
        setCheck('pool_enable',0);
        setText('vpn_min_address','');
        setText('vpn_max_address','');
        setText('vpn_subnet_mask','');
        setText('vpn_DNS_server','');
        
        SetIpsecAddress();
    }
}

function setControl(index)
{
    var record;
    var vpnrecord;
    selctIndex = index;

    if (index == -1) {
        if (IPSecVPN.length >= 11) {
            setDisplay('ConfigForm', 0);
            AlertEx(ipsec_language['ipsec_s113']);
            return;
        }

        AddFlag = true;
        record = new stIpSecVPN('','1','Site-to-Site','','','Tunnel','None','','','Main','PreShareKey','SHA256','AES128','MODP-768','IP','','','ESP','SHA256','AES128','None','SHA256','10800','3600','1843200','0','10','5','IKEv2','','');
        vpnrecord = new stAdressConfig('','','','','');
        setDisplay('ConfigForm', 1);
        setCtlDisplay(record, vpnrecord);
        setDisable('WANselect_select', 0);
        setDisplay("typeTR",1);
        setDisable("constsrvName",1);
        
        IPSecTypeSelect("Site-to-Site");
        IKEVersionSelect("IKEv2", false);
        IKEAuthenticationMethodSelect("PreShareKey");
        IKEIDTypeSelect("IP");
        IPSecTransformSelect("ESP");
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        AddFlag = false;
        record = IPSecVPN[index];
        ipsecAddressPool = record.AddressPool;

        if (ipsecAddressPool) {
            for ( var i = 0; i < VPN_VPNConfig.length - 1 ; i++) {
                if (ipsecAddressPool == VPN_VPNConfig[i].domain) {
                    vpnrecord = VPN_VPNConfig[i];
                }
            }
        }
        
        setDisplay('ConfigForm', 1);
        setCtlDisplay(record, vpnrecord);
        setDisable('WANselect_select', 0);
        
        IPSecTypeSelect(record.IPSecType);
        IKEVersionSelect(record.X_HW_IKEVersion, true);
        IKEAuthenticationMethodSelect(record.IKEAuthenticationMethod);
        IKEIDTypeSelect(record.IKEIDType);
        IPSecTransformSelect(record.IPSecTransform);
    }

    setDisable('btnApply_ex',0);
    setDisable('cancelValue',0);
    setDisable('Add_button',0);
    setDisable('Del_button',0);
}

function onClickAdd()
{
    clickAdd('IPsec');
}

function onAdvancedConfig() {
    if($("#hight_cfg_table").attr("AdvancedConfigFlag") == "1"){
        setDisplay("hight_cfg_table", 0);
        $("#hight_cfg_table").attr("AdvancedConfigFlag","0");
    }else{
        setDisplay("hight_cfg_table", 1);
        $("#hight_cfg_table").attr("AdvancedConfigFlag","1");
    }
}

function onClickDel()
{
    var noChooseFlag = true;
    var SubmitForm = new webSubmitForm();
    var del_url = 'complex.cgi?';
    var del_msg = '';

    if (IPSecVPN.length == 1) {
        AlertEx(ipsec_language['ipsec_s114']);
        return;
    }

    if (selctIndex == -1) {
        AlertEx(ipsec_language['ipsec_s115']);
        return;
    }

    for (var i = 0; i < IPSecVPN.length - 1; i++) {
        var tableID = i + 2;
        var rmId = getVirtualServerId(tableID,5);
        var rm = getElement(rmId);
        if (rm.checked == true) {
            noChooseFlag = false;
            del_msg = 'Del_x' + i + '=' + IPSecVPN[i].domain + '&';
            del_url += del_msg;
        }
    }
    del_url += 'RequestFile=html/bbsp/ipsec/ipsec.asp';
    if (noChooseFlag) {
        AlertEx(ipsec_language['ipsec_s116']);
        return ;
    }
    if (ConfirmEx(ipsec_language['ipsec_s117']) == false) {
        setDisable('Del_button',0);
        return;
    }

    SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));
    setDisable('btnApply_ex',1);
    setDisable('cancelValue',1);
    setDisable('Add_button',1);
    setDisable('Del_button',1);
    SubmitForm.setAction(del_url);
    SubmitForm.submit();
    DisableRepeatSubmit();
}

function IPSecTypeSelect(ipsecType) {
    if (ipsecType == 'Site-to-Site') {
        setDisplay('RemoteAddr_radioRow', 1);
        radioChooseRemoteAddrOption();
        setDisplay('RemoteSubnet_textRow', 1);
        setDisplay('poolEnableRow', 0);
        setDisplay('vpnMinAddressRow', 0);
        setDisplay('vpnMaxAddressRow', 0);
        setDisplay('vpnSubnetMaskRow', 0);
        setDisplay('vpnDnsServerRow', 0);
    } else if (ipsecType == 'PC-to-Site') {
        setDisplay('RemoteAddr_radioRow', 0);
        setDisplay('RemoteIP_textRow', 0);
        setDisplay('RemoteDomain_textRow', 0);
        setDisplay('RemoteSubnet_textRow', 0);
        setDisplay('poolEnableRow', 1);
        SetIpsecAddress();
    }
}

function SetIpsecAddress() {
    var enable = (getElement('pool_enable').checked == true ) ? 1 : 0;
    if (enable == 1) {
        setDisplay('vpnMinAddressRow', 1);
        setDisplay('vpnMaxAddressRow', 1);
        setDisplay('vpnSubnetMaskRow', 1);
        setDisplay('vpnDnsServerRow', 1);
    } else {
        setDisplay('vpnMinAddressRow', 0);
        setDisplay('vpnMaxAddressRow', 0);
        setDisplay('vpnSubnetMaskRow', 0);
        setDisplay('vpnDnsServerRow', 0);
    }
}

function IKEVersionSelect(IKEVersion, isOutput)
{
    if (IKEVersion == 'IKEv1') {
        if (isOutput == false) {
            if (ConfirmEx(ipsec_language['ipsec_s120']) == false) {
                setSelect('X_HW_IKEVersion_select', 'IKEv2');
                return;
            }
        }

        setDisplay('ExchangeMode_selectRow', 1);
        setDisplay('DPDEnable_chooseRow', 1);
        setDisplay('DPDThreshold_textRow', 1);
        setDisplay('DPDRetry_textRow', 1);
    } else if (IKEVersion == 'IKEv2') {
        setDisplay('ExchangeMode_selectRow', 0);
        setDisplay('DPDEnable_chooseRow', 0);
        setDisplay('DPDThreshold_textRow', 0);
        setDisplay('DPDRetry_textRow', 0);
    }
}

function IKEAuthenticationMethodSelect(IKEAuthenticationMethod)
{
    if (IKEAuthenticationMethod == 'PreShareKey') {
        setDisplay('IKEPreshareKey_textRow', 1);
        document.getElementById("IKEAuthenticationMethod_textRemark").innerHTML = "";
        setDisplay('ChooseCert_selectRow', 0);
    } else if (IKEAuthenticationMethod == 'RsaSignature') {
        setDisplay('IKEPreshareKey_textRow', 0);
        document.getElementById("IKEAuthenticationMethod_textRemark").innerHTML = ipsec_language['ipsec_s118'];
        setDisplay('ChooseCert_selectRow', 1);
    }
}

function ChooseCertSelect(cert)
{

}

function IKEIDTypeSelect(IKEIDType)
{
    if (IKEIDType == 'IP') {
        setDisplay('IKELocalName_textRow', 0);
        setDisplay('IKERemoteName_textRow', 0);
    } else if (IKEIDType == 'Name') {
        setDisplay('IKELocalName_textRow', 1);
        setDisplay('IKERemoteName_textRow', 1);
    }
}

function radioChooseRemoteAddrOption()
{
    var radioIndex = getRadioVal('idRadioDirectory');

    if (radioIndex == '1') {
        setDisplay('RemoteIP_textRow',1);
        setDisplay('RemoteDomain_textRow',0);
    } else {
        setDisplay('RemoteIP_textRow',0);
        setDisplay('RemoteDomain_textRow',1);
    }
}

function IPSecTransformSelect(transform)
{
    if (transform == 'ESP') {
        setDisplay('ESPAuthenticationAlgorithm_selectRow', 1);
        setDisplay('ESPEncryptionAlgorithm_selectRow', 1);
        setDisplay('AHAuthenticationAlgorithm_selectRow', 0);
    } else if (transform == 'AH') {
        setDisplay('ESPAuthenticationAlgorithm_selectRow', 0);
        setDisplay('ESPEncryptionAlgorithm_selectRow', 0);
        setDisplay('AHAuthenticationAlgorithm_selectRow', 1);
    }
}
function CancelConfig() {
    setDisplay("ConfigForm", 0);

    if (selctIndex == -1) {
        var tableRow = getElement("ipSecInst");
        if (tableRow.rows.length == 1) {
        }
        else if (tableRow.rows.length = 2) {
            addNullInst('IPsec');
        } else {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine('record_0');
        }
    } else {
        var optionrecord = VPNConfigInst[selctOptionIndex];
    }
}

function GetAbbreviationThumbprint(value)
{
    if (value.length < 16) {
        return value;
    }
    return value.substr(0, 4) + '......' + value.substr(value.length - 4, 4);
}

function WriteOption()
{
    for (var i = 0; i < ipsecCertInfoList.length; i++) {
        document.write('<option id="ipsecCert' + i + '" value="' + ipsecCertInfoList[i].domain + '">' + GetAbbreviationThumbprint(ipsecCertInfoList[i].thumbprint) + '</option>');
    }
}
</script>
</head>
<body>
<script language="JavaScript" type="text/javascript"> 
    if (appName == "Microsoft Internet Explorer") {
        document.write('<body onLoad="LoadFrame();" class="mainbody" scroll="auto">');
    } else {
        document.write('<body onLoad="LoadFrame();" class="mainbody" >');
    }

</script>
<form id="IPSecForm" name="IPSecForm"> 
  <script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("IPsectitle", GetDescFormArrayById(ipsec_language, "ipsec_s001"), GetDescFormArrayById(ipsec_language, "ipsec_s002"), false);
  </script>
  <div class="title_spread"></div>
  
  <script language="JavaScript" type="text/javascript">
    writeTabCfgHeader('IPsec',"100%");
  </script>
  <table class="tabal_bg" id="ipSecInst" width="100%" cellpadding="0" cellspacing="1"> 
    <tr class="head_title"> 
      <td id="VirtualServer_1_1_table" BindText='ipsec_s003'></td>
      <td id="VirtualServer_1_2_table" BindText='ipsec_s004'></td>
      <td id="VirtualServer_1_3_table" BindText='ipsec_s005'></td>
      <td id="VirtualServer_1_4_table" BindText='ipsec_s006'></td>
      <td id="VirtualServer_1_5_table" BindText='ipsec_s007'></td>
    </tr>
    <script language="JavaScript" type="text/javascript">
        if (IPSecVPN.length == 1) {
            document.write('<tr id="record_no"' 
                        + ' class="tabal_01 align_center" onclick="selectLine(this.id);">');
            document.write('<td id=' + getVirtualServerId(2,1) + '>--</td>');
            document.write('<td id=' + getVirtualServerId(2,2) + '>--</td>');
            document.write('<td id=' + getVirtualServerId(2,3) + '>--</td>');
            document.write('<td id=' + getVirtualServerId(2,4) + '>--</td>');
            document.write('<td id=' + getVirtualServerId(2,5) + '>--</td>');
            document.write('</tr>');
        } else {
            ShowIPSec();
        }
        </script> 
  </table> 
  <div class="button_spread"></div>
    <table class="table_button" id="cfg_title_table" width="100%"> 
      <tr align="right">
        <td >
          <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
          <button id="Add_button" name="Add_button" type="button" class="submit" onClick="onClickAdd();"><script>document.write(ipsec_language['bbsp_add']);</script></button>
          <button id="Del_button" name="Del_button" type="button" class="submit" onClick="onClickDel();"><script>document.write(ipsec_language['bbsp_del']);</script></button>
        </td>
      </tr>
    </table>

  <div id="ConfigForm"> 
  <div class="func_spread"></div>
   <table cellpadding="0" cellspacing="0" border="0" id="cfg_table" width="100%">

            <tr>
                <td class="table_title width_per25" style="display" BindText='ipsec_s008'></td> 
                <td class="table_right width_per25"> <input type='checkbox' id='Enable' name='Enable' > </td> 
            </tr>
          
          <tr id="IPSecType_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s009'></td> 
            <td class="table_right width_per75"> <select size="1" id='IPSecType_select' name='IPSecType_select' class="width_150px" onChange='IPSecTypeSelect(this.value)'>
                <option value="Site-to-Site" selected BindText='ipsec_s010'></option> 
                <option value="PC-to-Site" BindText='ipsec_s011'></option> 
              </select> </td> 
          </tr> 
            
          <tr id="LocalSubnet_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s012'></td>
            <td class="table_right width_per75"> <input type='text' id='LocalSubnet' name='LocalSubnet' size='20' maxlength='63'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s013']);</script></span>
            </td> 
          </tr> 
          
          <tr id="RemoteSubnet_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s014'></td>
            <td class="table_right width_per75"> <input type='text' id='RemoteSubnet' name='RemoteSubnet' size='20' maxlength='63'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s015']);</script></span>
            </td> 
          </tr>

          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s016'></td>
            <td class="table_right width_per75"> <select size="1" id='IPSecEncapsulationMode_select' name='IPSecEncapsulationMode_select' class="width_150px">
                <option value="Tunnel" selected BindText='ipsec_s017'></option>
                <option value="Transport" BindText='ipsec_s018'></option>
              </select> </td>
          </tr> 
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s019'></td> 
            <td class="table_right width_per75" id="IPSecOutInterfacetitle"> <select id="WANselect_select" name='WANselect_select' size="1" >  
            <script language="JavaScript" type="text/javascript">
                for (i = 0; i < WanInfo.length; i++) {
                    if ((WanInfo[i].ServiceList != 'TR069') && (WanInfo[i].ServiceList != 'VOIP') &&
                        (WanInfo[i].ServiceList != 'TR069_VOIP') && (WanInfo[i].Mode == 'IP_Routed') &&
                        (WanInfo[i].IPv4Enable == '1') && (WanInfo[i].X_HW_VXLAN_Enable != '1')) {
                        if (WanInfo[i].ServiceList == 'IPTV') {
                            continue;
                        } else {
                            document.write('<option value=' + WanInfo[i].domain 
                                           + ' id="wan_' + i + '" title="' + MakeWanName1(WanInfo[i]) 
                                           + '">'
                                           + MakeWanName1(WanInfo[i]) + '</option>');
                        }
                    }
                }
                var optionInterface=getElById('WANselect_select');
                if ((optionInterface.options.length > 0) && (optionInterface.selectedIndex >= 0)) {
                    getElById("IPSecOutInterfacetitle").title = optionInterface.options[optionInterface.selectedIndex].text;
                }
            </script> 
           </select> </td> 
          </tr>
          
          <tr id="RemoteAddr_radioRow">
            <td class="table_title width_per25" BindText='ipsec_s020'></td>
            <td class="table_right width_per75">
                <input name="idRadioDirectory" id="idRadioAllDirectory" type="radio" value="1" checked="checked" onclick="radioChooseRemoteAddrOption();"/> 
                <script>document.write(ipsec_language['ipsec_s021']);</script>
                <input name="idRadioDirectory" id="idRadioChooseDirectory" type="radio" value="0" onclick="radioChooseRemoteAddrOption();"/> 
                <script>document.write(ipsec_language['ipsec_s022']);</script>
            </td>
          </tr>
          
          <tr id="RemoteIP_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s021'></td> 
            <td class="table_right width_per75"> <input type='text' id='RemoteIP' name='RemoteIP' size='20' maxlength='63'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s023']);</script></span>
            </td> 
          </tr>
          
          <tr id="RemoteDomain_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s022'></td> 
            <td class="table_right width_per75"> <input type='text' id='RemoteDomain' name='RemoteDomain' size='20' maxlength='255'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s024']);</script></span>
            </td> 
          </tr>
          
          <tr id="IKEAuthenticationMethod_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s025'></td> 
            <td class="table_right width_per75"> <select size="1" id='IKEAuthenticationMethod_select' name='IKEAuthenticationMethod_select' class="width_150px" onChange='IKEAuthenticationMethodSelect(this.value)'>
                <option value="PreShareKey" selected  BindText='ipsec_s026'></option> 
                <option value="RsaSignature" BindText='ipsec_s027'></option> 
              </select> 
              <span class="gray" id="IKEAuthenticationMethod_textRemark"></span>
              </td>
          </tr>
          
          <tr id="ChooseCert_selectRow" style="display:none;"> 
            <td class="table_title width_per25" BindText='ipsec_s119'></td> 
            <td class="table_right width_per75"> <select size="1" id='ChooseCert_select' name='ChooseCert_select' class="width_150px" onChange='ChooseCertSelect(this.value)'>
                <script language="javascript">
                    WriteOption();
                </script>
              </select> 
              </td>
          </tr>
          
          <tr id="IKEPreshareKey_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s026'></td> 
            <td class="table_right width_per75"> <input autocomplete="new-password" type='password' id='IKEPreshareKey' name='IKEPreshareKey' size='20' maxlength='128'>
            <strong style="color:#FF0033">*</strong>
            <span class="gray"><script>document.write(ipsec_language['ipsec_s028']);</script></span>
            </td> 
          </tr>
          
          <tr id="IKEIDType_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s029'></td>
            <td class="table_right width_per75"> <select size="1" id='IKEIDType_select' name='IKEIDType_select' class="width_150px" onChange='IKEIDTypeSelect(this.value)'>
                <option value="IP" selected BindText='ipsec_s030'></option> 
                <option value="Name" BindText='ipsec_s031'></option>
              </select> </td>
          </tr>
          
          <tr id="IKELocalName_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s032'></td> 
            <td class="table_right width_per75"> <input type='text' id='IKELocalName' name='IKELocalName' size='20' maxlength='255'>
            <strong style="color:#FF0033">*</strong>
            <span class="gray"><script>document.write(ipsec_language['ipsec_s034']);</script></span>
            </td> 
          </tr>
              
          <tr id="IKERemoteName_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s033'></td>
            <td class="table_right width_per75"> <input type='text' id='IKERemoteName' name='IKERemoteName' size='20' maxlength='255'>
            <strong style="color:#FF0033">*</strong>
            <span class="gray"><script>document.write(ipsec_language['ipsec_s034']);</script></span>
            </td> 
          </tr>
          
          <tr>
            <td class="height15p"></td>
          </tr>
        </table>
          
        <input style="margin-bottom:10px;" class="NewDelbuttoncss" id="advancedConfigBtn" type="button" BindText='ipsec_s035' onclick="onAdvancedConfig();">
        <table id="hight_cfg_table" style="display:none;" AdvancedConfigFlag="0" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s036'></td>
            <td class="table_right width_per75">
                <select size="1" id='X_HW_IKEVersion_select' name='X_HW_IKEVersion_select' class="width_150px" onChange='IKEVersionSelect(this.value, false)'>
                <option value="IKEv1" selected BindText='ipsec_s037'></option>
                <option value="IKEv2" BindText='ipsec_s038'></option>
              </select> </td>
          </tr>
          
          <tr id="ExchangeMode_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s039'></td>
            <td class="table_right width_per75"> <select size="1" id='ExchangeMode_select' name='ExchangeMode_select' class="width_150px">
                <option value="Main" selected BindText='ipsec_s040'></option>
                <option value="Aggressive" BindText='ipsec_s041'></option>
              </select> </td>
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s042'></td> 
            <td class="table_right width_per75"> <select size="1" id='IKEAuthenticationAlgorithm_select' name='IKEAuthenticationAlgorithm_select' class="width_150px">
                <option value="SHA256" selected BindText='ipsec_s045'></option>
                <option value="SHA1" BindText='ipsec_s044'></option>
                <option value="MD5" BindText='ipsec_s043'></option>
              </select>
              <span class="gray"><script>document.write(ipsec_language['ipsec_Auth_suggestions']);</script></span>
            </td>
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s046'></td> 
            <td class="table_right width_per75"> <select size="1" id='IKEEncryptionAlgorithm_select' name='IKEEncryptionAlgorithm_select' class="width_150px">
                <option value="AES128" selected BindText='ipsec_s049'></option>
                <option value="AES192" BindText='ipsec_s050'></option>
                <option value="AES256" BindText='ipsec_s051'></option>
                <option value="3DES" BindText='ipsec_s048'></option>
                <option value="DES" BindText='ipsec_s047'></option>
              </select>
              <span class="gray"><script>document.write(ipsec_language['ipsec_Encryption_suggestions']);</script></span>
            </td> 
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s052'></td> 
            <td class="table_right width_per25"> <select size="1" id='IKEDHGroup_select' name='IKEDHGroup_select' class="width_150px">
                <option value="Group1" selected  BindText='ipsec_s053'></option> 
                <option value="Group2" BindText='ipsec_s054'></option>
                <option value="Group5" BindText='ipsec_s055'></option>
                <option value="Group14" BindText='ipsec_s056'></option>
              </select> </td> 
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s057'></td> 
            <td class="table_right width_per75"> <select size="1" id='IPSecPFS_select' name='IPSecPFS_select' class="width_150px">
                <option value="None" selected BindText='ipsec_s058'></option> 
                <option value="Group1" BindText='ipsec_s053'></option>
                <option value="Group2" BindText='ipsec_s054'></option>
                <option value="Group5" BindText='ipsec_s055'></option>
                <option value="Group14" BindText='ipsec_s056'></option>
              </select> </td> 
          </tr>
          
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s059'></td> 
            <td class="table_right width_per75"> <select size="1" id='IPSecTransform_select' name='IPSecTransform_select' class="width_150px" onChange='IPSecTransformSelect(this.value)'>
                <option value="ESP" selected BindText='ipsec_s060'></option>
                <option value="AH" BindText='ipsec_s061'></option>
              </select> </td> 
          </tr>
          
          <tr id="ESPAuthenticationAlgorithm_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s062'></td> 
            <td class="table_right width_per75"> <select size="1" id='ESPAuthenticationAlgorithm_select' name='ESPAuthenticationAlgorithm_select' class="width_150px">
                <option value="SHA256" selected BindText='ipsec_s045'></option>
                <option value="SHA1" BindText='ipsec_s044'></option>
                <option value="MD5" BindText='ipsec_s043'></option>
                <option value="None" BindText='ipsec_s058'></option>
              </select>
              <span class="gray"><script>document.write(ipsec_language['ipsec_Auth_suggestions']);</script></span>
            </td>
          </tr>
          
          <tr id="ESPEncryptionAlgorithm_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s063'></td> 
            <td class="table_right width_per75"> <select size="1" id='ESPEncryptionAlgorithm_select' name='ESPEncryptionAlgorithm_select' class="width_150px">
                <option value="AES128" selected BindText='ipsec_s049'></option>
                <option value="AES192" BindText='ipsec_s050'></option>
                <option value="AES256" BindText='ipsec_s051'></option>
                <option value="3DES" BindText='ipsec_s048'></option>
                <option value="DES" BindText='ipsec_s047'></option>
                <option value="None" BindText='ipsec_s058'></option>
              </select>
              <span class="gray"><script>document.write(ipsec_language['ipsec_Encryption_suggestions']);</script></span>
            </td>
          </tr>
          
          <tr id="AHAuthenticationAlgorithm_selectRow"> 
            <td class="table_title width_per25" BindText='ipsec_s064'></td> 
            <td class="table_right width_per75"> <select size="1" id='AHAuthenticationAlgorithm_select' name='AHAuthenticationAlgorithm_select' class="width_150px">
                <option value="SHA256" selected BindText='ipsec_s045'></option>
                <option value="SHA1" BindText='ipsec_s044'></option>
                <option value="MD5" BindText='ipsec_s043'></option>
              </select> </td>
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s065'></td> 
            <td class="table_right width_per75"> <input type='text' id='IKESAPeriod' name='IKESAPeriod' size='20' maxlength='5'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s066']);</script></span>
            </td> 
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s067'></td> 
            <td class="table_right width_per75"> <input type='text' id='IPSecSATimePeriod' name='IPSecSATimePeriod' size='20' maxlength='5'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s068']);</script></span>
            </td> 
          </tr>
          
          <tr> 
            <td class="table_title width_per25" BindText='ipsec_s069'></td> 
            <td class="table_right width_per75"> <input type='text' id='IPSecSATrafficPeriod' name='IPSecSATrafficPeriod' size='20' maxlength='10'>
                <strong style="color:#FF0033">*</strong>
                <span class="gray"><script>document.write(ipsec_language['ipsec_s070']);</script></span>
            </td> 
          </tr>
          <tr> 

          <tr id="DPDEnable_chooseRow">
                <td class="table_title width_per25" style="display" BindText='ipsec_s071'></td> 
                <td class="table_right width_per25"> <input type='checkbox' id='DPDEnable' name='DPDEnable' > </td> 
            </tr>
          
          <tr id="DPDThreshold_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s072'></td> 
            <td class="table_right width_per75"> <input type='text' id='DPDThreshold' name='DPDThreshold' size='20' maxlength='5'>
            <strong style="color:#FF0033">*</strong>
            <span class="gray"><script>document.write(ipsec_language['ipsec_s073']);</script></span>
            </td> 
          </tr>
          
          <tr id="DPDRetry_textRow"> 
            <td class="table_title width_per25" BindText='ipsec_s074'></td> 
            <td class="table_right width_per75"> <input type='text' id='DPDRetry' name='DPDRetry' size='20' maxlength='5'>
            <strong style="color:#FF0033">*</strong>
            <span class="gray"><script>document.write(ipsec_language['ipsec_s075']);</script></span>
            </td> 
          </tr>

            <tr id="poolEnableRow">
                <td class="table_title width_per25" style="" BindText='ipsec_s076'></td>
                <td class="table_right width_per25">
                    <input type="checkbox" id="pool_enable" name="pool_enable" onclick='SetIpsecAddress()'/>
                </td>
            </tr>

            <tr id="vpnMinAddressRow">
                <td class="table_title width_per25" BindText='ipsec_s077'></td>
                <td class="table_right width_per75">
                    <input type="text" id="vpn_min_address" name="vpn_min_address" maxlength="16" />
                    <strong style="color:#FF0033">*</strong>
                    <span class="gray" BindText='ipsec_s078'></span>
                </td>
            </tr>

            <tr id="vpnMaxAddressRow">
                <td class="table_title width_per25" BindText='ipsec_s079'></td>
                <td class="table_right width_per75">
                    <input type="text" id="vpn_max_address" name="vpn_max_address" maxlength="16" />
                    <strong style="color:#FF0033">*</strong>
                    <span class="gray" BindText='ipsec_s080'></span>
                </td>
            </tr>

            <tr id="vpnSubnetMaskRow">
                <td class="table_title width_per25" BindText='ipsec_s081'></td>
                <td class="table_right width_per75">
                    <input type="text" id="vpn_subnet_mask" name="vpn_subnet_mask" maxlength="16" />
                </td>
            </tr>

            <tr id="vpnDnsServerRow">
                <td class="table_title width_per25" BindText='ipsec_s082'></td>
                <td class="table_right width_per75">
                    <input type="text" id="vpn_DNS_server" name="vpn_DNS_server" maxlength="16" />
                </td>
            </tr>
    </table>

    <div class="button_spread"></div>
        <table width="100%" border="0" class="table_button">
            <tr align="right">
                <td class="width_per25"></td>
                <td>
                    <button name="btnApply_ex" id="btnApply_ex" type="button" class="submit" onClick="Submit(3);" enable=true ><script>document.write(ipsec_language['bbsp_app']);</script></button>
                    <button name="cancelValue" id="cancelValue" type="button" class="submit" style="padding-left:4px;" onClick="CancelConfig();"><script>document.write(ipsec_language['bbsp_cancel']);</script></button>
                </td> 
            </tr>
        </table>
    </div>
<script> 
     ParseBindTextByTagName(ipsec_language, "td", 1);
     ParseBindTextByTagName(ipsec_language, "span", 1);
     ParseBindTextByTagName(ipsec_language, "option", 1);
     ParseBindTextByTagName(ipsec_language, "input", 2);
</script> 
</form>
</body>
</html>