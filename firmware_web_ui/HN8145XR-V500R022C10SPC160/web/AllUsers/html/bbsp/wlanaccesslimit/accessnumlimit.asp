<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>

<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../../amp/common/<%HW_WEB_DeepCleanCache_Resource(wlan_list.asp);%>"></script>

<title>limitconfig</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(errdes.html);%>"></script>
<script language="JavaScript" type="text/javascript">

var maxAssociateNum = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_WIFIInfo.X_HW_DevAssociateNumManage.DevMaxAssociateNum);%>';

function ApDeviceList(domain, DevMaxAssociateNum)
{
    this.domain = domain;
    this.DevMaxAssociateNum = DevMaxAssociateNum;
}

var apDeviceList = new Array();
apDeviceList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}.X_HW_DevAssociateNumManage, DevMaxAssociateNum, ApDeviceList);%>;

function stDeviceInfo(domain, ModelName, DeviceAlias)
{
    this.domain                = domain;
    this.ModelName             = ModelName;
    this.DeviceAlias           = DeviceAlias;
}

var deviceInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, ModelName|X_HW_DeviceAlias, stDeviceInfo);%>;
var deviceInfo = deviceInfos[0];
var deviceName =deviceInfo.ModelName;
var deviceAlias = deviceInfo.DeviceAlias;

function ApDevice(domain, DeviceType, SyncStatus, APMacAddr, FttrEdgeOnt)
{
    this.domain = domain;
    this.DeviceType = DeviceType;
    this.SyncStatus = SyncStatus;
    this.APMacAddr = APMacAddr;
    this.FttrEdgeOnt = FttrEdgeOnt;
}
var apDeviceinfo = new Array();
apDeviceinfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}, DeviceType|SyncStatus|APMacAddr|FttrEdgeOnt, ApDevice);%>;

function USERDeviceInfo(Domain,MACAddress,Name) {
    this.Domain = Domain;
    this.MACAddress = MACAddress;
    this.Name = Name;
            }
var apDevHostinfo = new Array();
apDevHostinfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_HOMENET_NAME.hosts.{i}, MACAddress|Name, USERDeviceInfo);%>;

function CancelConfig()
{
    LoadFrame();
}

function ApplyConfig()
{
    if (CheckNumber(getValue('devinfo'), 1, 128) != true) {
        AlertEx(numlimitedge_language['limitedge_apnuminvalid']);
        return;
    }
    var Form = new webSubmitForm();
    var url='set.cgi?x=InternetGatewayDevice.X_HW_WIFIInfo.X_HW_DevAssociateNumManage';
    Form.addParameter('x.DevMaxAssociateNum', getValue('devinfo'));

    if ((apDeviceinfo.length - 1) != 0) {
        for (var i = 0; i < apDeviceinfo.length - 1; i++) {
            if ((apDeviceinfo[i].SyncStatus == 3) && (apDeviceinfo[i].FttrEdgeOnt == 1)) {
                if (CheckNumber(getValue('devinfo_' + i), 1, 128) != true) {
                    AlertEx(numlimitedge_language['limitedge_apnuminvalid']);
                    return;
                }
                var apIndex = apDeviceinfo[i].domain.split(".")[2];
                url += '&y_' + apIndex + '=InternetGatewayDevice.X_HW_APDevice.' + apIndex + '.X_HW_DevAssociateNumManage';
                Form.addParameter('y_' + apIndex + '.DevMaxAssociateNum',getValue('devinfo_' + i));
            }
        }
    }

    url += '&RequestFile=html/bbsp/wlanaccesslimit/accessnumlimit.asp';
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction(url);
    Form.submit();
}
function GetHostName(index)
{
    var apDevHostLen = apDevHostinfo.length - 1;
    for (var i = 0; i < apDevHostLen; i++) {
        if (apDeviceinfo[index].APMacAddr.toUpperCase() == apDevHostinfo[i].MACAddress.toUpperCase()) {
            var apDevName = apDeviceinfo[index].DeviceType;
            if (apDevHostinfo[i].Name != '') {
                apDevName += '(' + apDevHostinfo[i].Name + ')';
            }
            document.getElementById("apdevname_" + index).innerHTML = apDevName;
            return;
        }
    }
}

function LoadFrame()
{
    var accessNumber = '';
    if (maxAssociateNum == 0) {
        accessNumber = 128;
    } else {
        accessNumber = maxAssociateNum;
    }

    setText("devinfo", accessNumber);

    var apdevInfoLen = apDeviceinfo.length - 1;
    if (apdevInfoLen != 0) {
        for (var index = 0; index < apdevInfoLen; index++) {
            if ((apDeviceinfo[index].SyncStatus == 3) && (apDeviceinfo[index].FttrEdgeOnt == 1)) {
            var apMaxaccessNum = 128;
            if (apDeviceList[index].DevMaxAssociateNum != 0) {
                apMaxaccessNum = apDeviceList[index].DevMaxAssociateNum;
            }

            setText("devinfo_" + index, apMaxaccessNum);
                GetHostName(index);
            }
        }
    }

}

</script>

</head>
<body onLoad="LoadFrame();" class="mainbody">
<div>
    <form id="ConfigForm">
        <script language="JavaScript" type="text/javascript">
            HWCreatePageHeadInfo("accessnumlimit", GetDescFormArrayById(numlimitedge_language, "limitedge_mune"), GetDescFormArrayById(numlimitedge_language, "limitedge_title"), false);
        </script>
        <div class="title_spread"></div>
        <table class='width_per100' border="0" align="center" cellpadding="0" cellspacing="1">
                <tr class="head_title">
                    <td class ="devIndex"><script>document.write(numlimitedge_language['limitedge_index']);</script></td>
                    <td class ="devName"><script>document.write(numlimitedge_language['limitedge_title_apname']);</script></td>
                    <td class ="devAccessNum"><script>document.write(numlimitedge_language['limitedge_title_apnum']);</script></td>
                </tr>

                <tr class="tabal_01 align_center">
                    <td style="width:10%">1</td>
                    <td style="width:50%"><script>
                        var deviceStr = deviceName;
                        if (deviceAlias != '') {
                            deviceStr += '(' + deviceAlias + ')';
                        }

                        document.write(deviceStr);
                    </script></td></td>
                    <td class="table_right width_per15" align="left" style="width:40%"><input type='text' id='devinfo' style='width:60%'/><span>(1- 128)</span>
                    </td>
                </tr>

                <script language="JavaScript" type="text/javascript">
                var apIndex = 1;
                if ((apDeviceinfo.length - 1) != 0) {
                    for (var index = 0; index < apDeviceinfo.length - 1; index++) {
                        if ((apDeviceinfo[index].SyncStatus == 3) && (apDeviceinfo[index].FttrEdgeOnt == 1)) {
                            apIndex += 1;
                            document.write('<tr class="tabal_01 align_center">' + 
                            '<td style="width:10%' + bottomBorderClass(true) + '">' + apIndex + '</td>' +
                            '<td id = "apdevname_' + index + '" style="width:50%"></td>' +
                            '<td class = "table_right width_per15" align="left" style="width:40%">' +
                            '<input type = "text" id ="devinfo_' + index + '" style="width:60%"/><span>(1- 128)</span> </td>' + '</tr>');
                        }
                    }
                }
            </script>
        </table>
    </form>

    <div class="title_spread"></div>
    <table id="applycancel" width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
        <tr>
            <td class='width_per30'></td>
            <td class="table_submit">
            <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
                <button id="btnApply1" name="btnApply1" type="button" class="ApplyButtoncss buttonwidth_100px"  onClick="ApplyConfig();"><script>document.write(numlimitedge_language['limitedge_apply']);</script></button>
                <button id="btnCancle1" name="btnCancle1" type="button" class="CancleButtonCss buttonwidth_100px"   onClick="CancelConfig();"><script>document.write(numlimitedge_language['limitedge_cancel']);</script></button> </td>
        </tr>
    </table>

    <script>
        ParseBindTextByTagName(numlimitedge_language, "td", 1);
        ParseBindTextByTagName(numlimitedge_language, "input", 2);
        ParseBindTextByTagName(numlimitedge_language, "div", 1);
    </script>
</div>
</body>
</html>