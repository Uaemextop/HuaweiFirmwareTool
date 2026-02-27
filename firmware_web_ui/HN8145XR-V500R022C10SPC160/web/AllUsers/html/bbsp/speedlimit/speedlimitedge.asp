<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>

<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(common.js);%>"></script>
<script language="javascript" src="../common/<%HW_WEB_DeepCleanCache_Resource(lanmodelist.asp);%>"></script>
<script language="javascript" src="../../amp/common/<%HW_WEB_DeepCleanCache_Resource(wlan_list.asp);%>"></script>

<title>vlanconfig</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(errdes.html);%>"></script>

<style>
.InputTime
    {
        width:20px;
    }
.InputYearTime
    {
        width:40px;
    }
</style>

<script language="JavaScript" type="text/javascript">

var TableClass = new stTableClass("table_title width_per25", "table_right width_per75", "", "Select");
var selctIndex = -1;
var TableName = "speedLimitInst";
var speedLimtMin = 0;
var speedLimtMax = 10240;
var yearMin = 1970;
var yearMax = 2100;
var monthMin = 1;
var monthMax = 12;
var dayMin = 1;
var dayMax = 31;
var leapYearInMonth = new Array(31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
var normalYearInMonth = new Array(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);

function SpeedLimitInfo(domain, apIndex, apMac, apName, apIp, upLimit, downLimit, onlineCtrl, startTime, endTime) {
    this.domain = domain;
    this.apIndex = apIndex;
    this.apMac = apMac;
    this.apName = apName;
    this.apIp = apIp;
    this.upLimit = upLimit;
    this.downLimit = downLimit;
    this.onlineCtrl = onlineCtrl;
    this.startTime = startTime;
    this.endTime = endTime;
}

var speedLimitInfoList = new Array();

function HomenetNameHost(domain, MACAddress, Name) {
    this.domain = domain;
    this.MACAddress = MACAddress;
    this.Name = Name;
}
var apHomenetNameHost = new Array();
apHomenetNameHost = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_HOMENET_NAME.hosts.{i}, MACAddress|Name, HomenetNameHost);%>;

function UserDeviceInfo(domain, IpAddr, MacAddr, HostName, UserDevAlias) {
    this.domain = domain;
    this.IpAddr	= IpAddr;
    this.MacAddr = MacAddr;
    this.HostName = HostName;
    this.UserDevAlias = UserDevAlias;
}

var userDevinfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.X_HW_UserDev.{i}, IpAddr|MacAddr|HostName|UserDevAlias, UserDeviceInfo);%>;

function ApObjInfo(domain, Mac, UpRate, DownRate, OnlineControlEnable, OnlineStartDate, OnlineEndDate) {
    this.domain = domain;
    this.Mac = Mac;
    this.UpRate = UpRate;
    this.DownRate = DownRate;
    this.OnlineControlEnable = OnlineControlEnable;
    this.OnlineStartDate = OnlineStartDate;
    this.OnlineEndDate = OnlineEndDate;
}

var apObjInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.ApFeature.ApObj.{i}, Mac|UpRate|DownRate|OnlineControlEnable|OnlineStartDate|OnlineEndDate, ApObjInfo);%>;
var apSegregateEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.ApFeature.BrApSegregateEnable);%>';

function stApDeviceList(domain, ApOnlineFlag,APMacAddr)
{
    this.domain = domain;
    this.ApOnlineFlag = ApOnlineFlag;
    this.APMacAddr = APMacAddr;
}

var apDeviceList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}, ApOnlineFlag|APMacAddr, stApDeviceList);%>;
var idx = 0;
for (var i = 0; i < apDeviceList.length - 1; i++) {
    if (apDeviceList[i].ApOnlineFlag == '1') {
        speedLimitInfoList[idx] = new SpeedLimitInfo();
        speedLimitInfoList[idx].apMac = apDeviceList[i].APMacAddr;
        speedLimitInfoList[idx].upLimit = "0";
        speedLimitInfoList[idx].downLimit = "0";
        speedLimitInfoList[idx].onlineCtrl = '0';
        speedLimitInfoList[idx].startTime = "--";
        speedLimitInfoList[idx].endTime = "--";
        speedLimitInfoList[idx].apIndex = idx + 1;
        speedLimitInfoList[idx].domain = "";
        GetUserInfo(idx);
        GetSpeedLimit(idx);
        idx++;
    }
}

function GetUserInfo(idx)
{
    for (var i = 0; i < apHomenetNameHost.length - 1; i++) {
        if (apHomenetNameHost[i].MACAddress.toLowerCase() == speedLimitInfoList[idx].apMac.toLowerCase()) {
            speedLimitInfoList[idx].apName = apHomenetNameHost[i].Name;
            break;
        }
    }
    for (var i = 0; i < userDevinfo.length - 1; i++) {
        if (userDevinfo[i].MacAddr.toLowerCase() == speedLimitInfoList[idx].apMac.toLowerCase()) {
            speedLimitInfoList[idx].apIp = userDevinfo[i].IpAddr;
            if (speedLimitInfoList[idx].apName == "") {
                speedLimitInfoList[idx].apName = userDevinfo[i].HostName;
            }
            break;
        }
    }
}

function GetSpeedLimit(idx)
{
    for (var i = 0; i < apObjInfoList.length - 1; i++) {
        if (apObjInfoList[i].Mac.toLowerCase() == speedLimitInfoList[idx].apMac.toLowerCase()) {
            speedLimitInfoList[idx].domain = apObjInfoList[i].domain;
            speedLimitInfoList[idx].upLimit = apObjInfoList[i].UpRate;
            speedLimitInfoList[idx].downLimit = apObjInfoList[i].DownRate;
            speedLimitInfoList[idx].onlineCtrl = apObjInfoList[i].OnlineControlEnable;
            if (apObjInfoList[i].OnlineStartDate == "") {
                speedLimitInfoList[idx].startTime = "--";
            } else {
                speedLimitInfoList[idx].startTime = apObjInfoList[i].OnlineStartDate;
            }
            if (apObjInfoList[i].OnlineEndDate == "") {
                speedLimitInfoList[idx].endTime = "--";
            } else {
                speedLimitInfoList[idx].endTime = apObjInfoList[i].OnlineEndDate;
            }
            break;
        }
    }
}


function CancelConfig()
{
    setDisplay('speedLimitform', 0);
}

function CheckLeapYear(year)
{
    if ((year % 400 == 0) || ((year % 4 == 0) && (year % 100 != 0))) {
        return true;
    }
    return false;
}

function CheckTimeVaild(year, month, day)
{
    var inMonth = normalYearInMonth;
    if (CheckLeapYear(year)) {
        inMonth = leapYearInMonth; 
    }
    if (day > inMonth[month - 1]) {
        return false;
    }
    return true;
}

function CheckTimeRange()
{
    var startYearVar = parseInt(getValue('startYear'));
    var startMonthVal = parseInt(getValue('startMonth'));
    var startDayVal = parseInt(getValue('startDay'));
    var endYearVal = parseInt(getValue('endYear'));
    var endMonthVal = parseInt(getValue('endMonth'));
    var endDayVal = parseInt(getValue('endDay'));
    if (startYearVar > endYearVal) {
        return false;
    } else if (startYearVar < endYearVal) {
        return true;
    } else {
        if (startMonthVal > endMonthVal) {
            return false;
        } else if (startMonthVal < endMonthVal) {
            return true;
        } else {
            if (startDayVal > endDayVal) {
                return false;
            } else if (startDayVal < endDayVal) {
                return true;
            }
        }
    }
    return true;
}

function CheckForm()
{
    var upLimit = removeInvisibleChar(getValue('upLimit'));
    var downLimit = removeInvisibleChar(getValue('downLimit'));
    var apName = getValue('apName');

    if ((apName == "") || (apName == null)) {
        AlertEx(speedlimitedge_language['limitedge_apname_invalid']);
        return false;
    } else {
        if (apName.length > 256) {
            AlertEx(speedlimitedge_language['limitedge_apname_invalid']);
            return false;
        }
    }

    if (CheckNumber(upLimit, speedLimtMin, speedLimtMax) == false) {
        AlertEx(speedlimitedge_language['limitedge_uplimit_invalid']);
        return false;
    }
    if (CheckNumber(downLimit, speedLimtMin, speedLimtMax) == false) {
        AlertEx(speedlimitedge_language['limitedge_downlimit_invalid']);
        return false;
    }
    if (getCheckVal('onlineCtrlEnable') == '1') {
        var startYearVar = parseInt(getValue('startYear'));
        var startMonthVal = parseInt(getValue('startMonth'));
        var startDayVal = parseInt(getValue('startDay'));
        var endYearVal = parseInt(getValue('endYear'));
        var endMonthVal = parseInt(getValue('endMonth'));
        var endDayVal = parseInt(getValue('endDay'));
        if (CheckNumber(startYearVar, yearMin, yearMax) == false) {
            AlertEx(speedlimitedge_language['limitedge_title_starttime_invalid']);
            return false;
        }
        if (CheckNumber(startMonthVal, monthMin, monthMax) == false) {
            AlertEx(speedlimitedge_language['limitedge_title_starttime_invalid']);
            return false;
        }
        if (CheckNumber(startDayVal, dayMin, dayMax) == false) {
            AlertEx(speedlimitedge_language['limitedge_title_starttime_invalid']);
            return false;
        }
        if (CheckNumber(endYearVal, yearMin, yearMax) == false) {
            AlertEx(speedlimitedge_language['limitedge_title_endtime_invalid']);
            return false;
        }
        if (CheckNumber(endMonthVal, monthMin, monthMax) == false) {
            AlertEx(speedlimitedge_language['limitedge_title_endtime_invalid']);
            return false;
        }
        if (CheckNumber(endDayVal, dayMin, dayMax) == false) {
            AlertEx(speedlimitedge_language['limitedge_title_endtime_invalid']);
            return false;
        }
        if (!CheckTimeRange()) {
            AlertEx(speedlimitedge_language['limitedge_title_timerange_error']);
            return false;
        }
        if (!CheckTimeVaild(startYearVar, startMonthVal, startDayVal)) {
            AlertEx(speedlimitedge_language['limitedge_title_starttime_invalid']);
            return false;
        }
        if (!CheckTimeVaild(endYearVal, endMonthVal, endDayVal)) {
            AlertEx(speedlimitedge_language['limitedge_title_endtime_invalid']);
            return false;
        }
    }
    return true;
}

function GetApNameDomain(mac)
{
    for (var i = 0; i < apHomenetNameHost.length - 1; i++) {
        if (apHomenetNameHost[i].MACAddress.toLowerCase() == mac.toLowerCase()) {
            return apHomenetNameHost[i].domain;
        }
    }
    return "";
}

function ApplyConfig()
{
    if (CheckForm() != true) {
        return;
    }
    var Form = new webSubmitForm();
    setDisable('btnApply1', 1);
    Form.addParameter('Add_y.UpRate', removeInvisibleChar(getValue('upLimit')));
    Form.addParameter('Add_y.DownRate', removeInvisibleChar(getValue('downLimit')));
    var onlineCtrlVal = getCheckVal('onlineCtrlEnable');
    Form.addParameter('Add_y.OnlineControlEnable', onlineCtrlVal);
    if (onlineCtrlVal == '1') {
        var startTimeVal = getValue('startYear') + "-" + getValue('startMonth') + "-" + getValue('startDay');
        var endTimeVal = getValue('endYear') + "-" + getValue('endMonth') + "-" + getValue('endDay');
        Form.addParameter('Add_y.OnlineStartDate', startTimeVal);
        Form.addParameter('Add_y.OnlineEndDate', endTimeVal);
    }
    Form.addParameter('x.Name', getValue('apName'));
    if (speedLimitInfoList[selctIndex].domain == "") {
        Form.addParameter('Add_y.Mac', speedLimitInfoList[selctIndex].apMac);
        Form.setAction('complex.cgi?' + 'x=' + GetApNameDomain(speedLimitInfoList[selctIndex].apMac) + '&Add_y=InternetGatewayDevice.ApFeature.ApObj' + '&RequestFile=html/bbsp/speedlimit/speedlimitedge.asp');
    } else {
        Form.setAction('set.cgi?' + 'x=' + GetApNameDomain(speedLimitInfoList[selctIndex].apMac) + '&Add_y=' + speedLimitInfoList[selctIndex].domain + '&RequestFile=html/bbsp/speedlimit/speedlimitedge.asp');
    }

    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function LoadFrame()
{
    setCheck("segregatedEnable", apSegregateEnable);
}

function OnSegregatedEnable()
{
    var Form = new webSubmitForm();
    Form.addParameter('x.BrApSegregateEnable', getCheckVal('segregatedEnable'));
    Form.setAction('set.cgi?x=InternetGatewayDevice.ApFeature&RequestFile=html/bbsp/speedlimit/speedlimitedge.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function OnOnlineCtrlEnable()
{
    if (getCheckVal('onlineCtrlEnable') == "0") {
        SetTimeDisable(1);
    } else {
        SetTimeDisable(0);
    }
}

function SetTimeDisable(val)
{
    setDisable('startYear', val);
    setDisable('startMonth', val);
    setDisable('startDay', val);
    setDisable('endYear', val);
    setDisable('endMonth', val);
    setDisable('endDay', val);
}

function FillCtrl(index)
{
    var curInfo = speedLimitInfoList[index];

    getElById("apMac").innerHTML = htmlencode(curInfo.apMac);
    getElById("apIp").innerHTML = htmlencode(curInfo.apIp);
    setText('apName', curInfo.apName);
    setText('upLimit', curInfo.upLimit);
    setText('downLimit', curInfo.downLimit);
    setCheck('onlineCtrlEnable', curInfo.onlineCtrl);
    if (curInfo.startTime == "--") {
        setText('startYear', "");
        setText('startMonth', "");
        setText('startDay', "");
    } else {
        var time = curInfo.startTime.split('-');
        setText('startYear', time[0]);
        setText('startMonth', time[1]);
        setText('startDay', time[2]);
    }
    if (curInfo.endTime == "--") {
        setText('endYear', "");
        setText('endMonth', "");
        setText('endDay', "");
    } else {
        var time = curInfo.endTime.split('-');
        setText('endYear', time[0]);
        setText('endMonth', time[1]);
        setText('endDay', time[2]);
    }
    if (curInfo.onlineCtrl == "0") {
        SetTimeDisable(1);
    } else {
        SetTimeDisable(0);
    }
}

function setControl(index)
{
    selctIndex = index;
    setDisplay('speedLimitform', 1);
    FillCtrl(index);
}


function InitTableData()
{
    var TableDataInfo = new Array();
    var ColumnNum = 9;
    var ShowButtonFlag = false;
    var idx = 0;
    if (speedLimitInfoList.length == 0) {
        TableDataInfo[idx] = new SpeedLimitInfo();
        TableDataInfo[idx].apIndex = '--';
        TableDataInfo[idx].apMac = '--';
        TableDataInfo[idx].apName = '--';
        TableDataInfo[idx].apIp = '--';
        TableDataInfo[idx].upLimit = '--';
        TableDataInfo[idx].downLimit = '--';
        TableDataInfo[idx].onlinectrlenable = '--';
        TableDataInfo[idx].startTime = '--';
        TableDataInfo[idx].endTime = '--';
        HWShowTableListByType(1, TableName, ShowButtonFlag, ColumnNum, TableDataInfo, speedLimitlistInfo, speedlimitedge_language, null);
        return;
    } else {
        for (var i = 0; i < speedLimitInfoList.length; i++) {
            TableDataInfo[idx] = new SpeedLimitInfo();
            TableDataInfo[idx].apIndex = speedLimitInfoList[i].apIndex;
            TableDataInfo[idx].apMac = speedLimitInfoList[i].apMac;
            TableDataInfo[idx].apName = speedLimitInfoList[i].apName;
            TableDataInfo[idx].apIp = speedLimitInfoList[i].apIp;
            TableDataInfo[idx].upLimit = speedLimitInfoList[i].upLimit;
            TableDataInfo[idx].downLimit = speedLimitInfoList[i].downLimit;
            TableDataInfo[idx].startTime = speedLimitInfoList[i].startTime;
            TableDataInfo[idx].endTime = speedLimitInfoList[i].endTime;
            TableDataInfo[idx].onlinectrlenable = speedlimitedge_language['limitedge_no'];
            if (speedLimitInfoList[i].onlineCtrl == '1') {
                TableDataInfo[idx].onlinectrlenable = speedlimitedge_language['limitedge_yes'];;
            }
            idx++;
        }
        TableDataInfo.push(null);
        HWShowTableListByType(1, TableName, ShowButtonFlag, ColumnNum, TableDataInfo, speedLimitlistInfo, speedlimitedge_language, null);
    }
}

</script>

</head>
<body onLoad="LoadFrame();" class="mainbody">
    <script language="JavaScript" type="text/javascript">
        HWCreatePageHeadInfo("speedlimitedge", GetDescFormArrayById(speedlimitedge_language, "limitedge_mune"), GetDescFormArrayById(speedlimitedge_language, "limitedge_title"), false);
    </script>
    <div class="title_spread"></div>
    <div class="func_title" BindText="limitedge_segregated"></div>
    

    <div id='wlanswitch'>
        <table cellspacing="0" cellpadding="0" width="100%" class="table_button" id="segregatedOnOff">
          <tr>
            <td><input type='checkbox' name='segregatedEnable' id='segregatedEnable' onClick='OnSegregatedEnable();' value="ON">
              <script>document.write(speedlimitedge_language['limitedge_segregatedenable']);  </script></input></td>
          </tr>
        </table>
    </div>
    <div class="title_spread"></div>
    <div class="title_spread"></div>
    <div class="func_title" BindText="limitedge_apspeedlimit"></div>
    <script type="text/javascript">
    var speedLimitlistInfo = new Array(new stTableTileInfo("limitedge_index", "align_center width_per5", "apIndex"),
                                        new stTableTileInfo("limitedge_apname", "align_center", "apName", false, 16),
                                        new stTableTileInfo("limitedge_apmac", "align_center", "apMac"),
                                        new stTableTileInfo("limitedge_apip", "align_center", "apIp"),
                                        new stTableTileInfo("limitedge_uplimit", "align_center", "upLimit"),
                                        new stTableTileInfo("limitedge_downlimit", "align_center", "downLimit"),
                                        new stTableTileInfo("limitedge_onlinectrlenable", "align_center", "onlinectrlenable"),
                                        new stTableTileInfo("limitedge_starttime", "align_center", "startTime"),
                                        new stTableTileInfo("limitedge_endtime", "align_center", "endTime"),
                                        null);
    InitTableData();

    </script>
    <div class="title_spread"></div>
    <form id="speedLimitform" style="display:none;">
        <table border="0" cellpadding="0" cellspacing="1"  width="100%"> 
            <li id="apMac" RealType="HtmlText" DescRef="limitedge_title_apmac" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="" InitValue="Empty" ClickFuncApp="Empty"/>
            <li id="apIp" RealType="HtmlText" DescRef="limitedge_title_apip" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="" InitValue="Empty" ClickFuncApp="Empty"/>
            <li id="apName" RealType="TextBox" DescRef="limitedge_title_apname" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="" InitValue="Empty" ClickFuncApp="Empty"/>
            <li id="upLimit" RealType="TextBox" DescRef="limitedge_title_uplimit" RemarkRef="limitedge_limit_tip" ErrorMsgRef="Empty" Require="FALSE" BindField="" InitValue="Empty" ClickFuncApp="Empty"/>
            <li id="downLimit" RealType="TextBox" DescRef="limitedge_title_downlimit" RemarkRef="limitedge_limit_tip" ErrorMsgRef="Empty" Require="FALSE" BindField="" InitValue="Empty" ClickFuncApp="Empty"/>
            <li id="onlineCtrlEnable" RealType="CheckBox" DescRef="limitedge_title_onlineCtrlEnable" RemarkRef="limitedge_title_onlineCtrlEnable_tip" ErrorMsgRef="Empty" Require="FALSE" BindField="" InitValue="" ClickFuncApp="onClick=OnOnlineCtrlEnable"/>
            <li id="startYear" RealType="TextOtherBox" DescRef="limitedge_title_starttime" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="" Elementclass="InputYearTime"  MaxLength="4"
                    InitValue="[{Type:'span',Item:[{AttrName:'id',AttrValue:'start_time_year'}]}, {Type:'input',Item:[{AttrName:'id',AttrValue:'startMonth'},
                    {AttrName:'BindFileld', AttrValue:'Empty'},{AttrName:'MaxLength', AttrValue:'2'},{AttrName:'class', AttrValue:'InputTime'}]},{Type:'span',Item:[{AttrName:'id',AttrValue:'start_time_month'}]},
                    {Type:'input',Item:[{AttrName:'id',AttrValue:'startDay'}, {AttrName:'BindFileld', AttrValue:'Empty'},{AttrName:'MaxLength', AttrValue:'2'},{AttrName:'class', AttrValue:'InputTime'}]},
                    {Type:'span',Item:[{AttrName:'id',AttrValue:'start_time_day'}]}]"/>
            <li id="endYear" RealType="TextOtherBox" DescRef="limitedge_title_endtime" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="" Elementclass="InputYearTime"  MaxLength="4"
                    InitValue="[{Type:'span',Item:[{AttrName:'id',AttrValue:'end_time_year'}]}, {Type:'input',Item:[{AttrName:'id',AttrValue:'endMonth'},
                    {AttrName:'BindFileld', AttrValue:'Empty'},{AttrName:'MaxLength', AttrValue:'2'},{AttrName:'class', AttrValue:'InputTime'}]},{Type:'span',Item:[{AttrName:'id',AttrValue:'end_time_month'}]},
                    {Type:'input',Item:[{AttrName:'id',AttrValue:'endDay'}, {AttrName:'BindFileld', AttrValue:'Empty'},{AttrName:'MaxLength', AttrValue:'2'},{AttrName:'class', AttrValue:'InputTime'}]},
                    {Type:'span',Item:[{AttrName:'id',AttrValue:'end_time_day'}]}]"/>
            <script>
                speedLimitFormList = HWGetLiIdListByForm("speedLimitform",null);
                HWParsePageControlByID("speedLimitform", TableClass, speedlimitedge_language, null);
                document.getElementById("start_time_year").innerHTML = '&nbsp;' + speedlimitedge_language['limitedge_year'] + '&nbsp;';
                document.getElementById("start_time_month").innerHTML = '&nbsp;' + speedlimitedge_language['limitedge_month'] + '&nbsp;';
                document.getElementById("start_time_day").innerHTML = '&nbsp;' + speedlimitedge_language['limitedge_day'] + '&nbsp;';
                document.getElementById("end_time_year").innerHTML = '&nbsp;' + speedlimitedge_language['limitedge_year'] + '&nbsp;';
                document.getElementById("end_time_month").innerHTML = '&nbsp;' + speedlimitedge_language['limitedge_month'] + '&nbsp;';
                document.getElementById("end_time_day").innerHTML = '&nbsp;' + speedlimitedge_language['limitedge_day'] + '&nbsp;';
            </script> 
        </table>

        <table id="applycancel" width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
            <tr>
                <td class='width_per30'></td>
                <td class="table_submit">
                <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
                    <button id="btnApply1" name="btnApply1" type="button" class="ApplyButtoncss buttonwidth_100px"  onClick="ApplyConfig(0);"><script>document.write(speedlimitedge_language['limitedge_apply']);</script></button>
                    <button id="btnCancle1" name="btnCancle1" type="button" class="CancleButtonCss buttonwidth_100px"   onClick="CancelConfig();"><script>document.write(speedlimitedge_language['limitedge_cancel']);</script></button> </td>
            </tr>
        </table>
    </form>

    <script>
        ParseBindTextByTagName(speedlimitedge_language, "td", 1);
        ParseBindTextByTagName(speedlimitedge_language, "input", 2);
        ParseBindTextByTagName(speedlimitedge_language, "div", 1);
    </script>
</body>
</html>