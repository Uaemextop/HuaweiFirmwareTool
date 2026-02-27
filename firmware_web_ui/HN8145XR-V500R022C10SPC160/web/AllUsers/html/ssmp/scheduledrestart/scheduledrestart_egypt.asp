
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<link rel="stylesheet" href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet" href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<title>Automatic Reboot</title>
<style>
  .table_content {
    background-color: #FFFFFF;
    height: 35px;
    line-height: 150%;
    font-size: 14px;
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    color: #666666;
    text-align: center;
  }
</style>
<script language="JavaScript" type="text/javascript">
var systemTime = '<%HW_WEB_GetSystemTime();%>';
var syncStatus = '<%WEB_GetTimeSyncStatus();%>';
var weekNameArray = new Array("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday");
var weekNumArray = new Array("1", "2", "3", "4", "5", "6", "7");
var rebootEnable = "<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_AutoRebootByWeek.Enable);%>";
var timeListStr = "<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_AutoRebootByWeek.RebootStartTime);%>";
var dayListStr = "<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_AutoRebootByWeek.RepeatDay);%>";

function GetLanguageDesc(Name)
{
    return cfg_rebootdule_language[Name];
}

function ParseSystemTime(systemTime)
{
    if (systemTime == "") {
        systemTime = "1970-01-01 01:01";
    }

    document.getElementById('time').innerHTML = htmlencode(systemTime);
}

function ParseSyncStatus(syncStatus)
{
    document.getElementById('sync').innerHTML = GetLanguageDesc("ssmp_rebootdule_not_synced");
    if (syncStatus == "1") {
        document.getElementById('sync').innerHTML = GetLanguageDesc("ssmp_rebootdule_synced");
    }
}

function rebootTimeSplit(strTimeStart, day)
{
    var i = strTimeStart.indexOf(':', 0);
    if (i != 0) {
        setText('time_start_hours_' + day, strTimeStart.substr(0, i));
        var mins = parseInt(strTimeStart.substr(i + 1));
        setText('time_start_min_' + day, mins >= 30 ? "30" : "00");
    }
}

function rebootRepeatSplit(timeListStr, dayListStr)
{
    var dayList = dayListStr.split(",");
    var timeList = timeListStr.split(",");

    for (var i = 0; i < weekNumArray.length; i++) {
        rebootTimeSplit(":00", weekNumArray[i]);
    }

    for (var i = 0; i < dayList.length; i++) {
        rebootTimeSplit(timeList[i], parseInt(dayList[i]));
    }
}

function LoadFrame()
{
    ParseSystemTime(systemTime);
    ParseSyncStatus(syncStatus);
    setCheck('rebootChEnable', rebootEnable);
    setDisplay('rebootCtrlTable',rebootEnable);
    setDisplay('rebootApplyTable',rebootEnable);

    if (rebootEnable == 1) {
        rebootRepeatSplit(timeListStr, dayListStr);
    }  
}

function rebootSetEnable()
{
    var Form = new webSubmitForm();
    var enable = getCheckVal('rebootChEnable');

    setDisplay('rebootCtrlTable', enable);
    setDisplay('rebootApplyTable', enable);

    if ((rebootEnable == 0) && (timeListStr == "")) {
        return;
    }

    Form.addParameter('x.Enable', enable);
    Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_AutoRebootByWeek' +
                   '&RequestFile=html/ssmp/scheduledrestart/scheduledrestart_egypt.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function isIntegerOrNull(value)
{
    if ((true != isPlusInteger(value)) && ('' != value)) {
        return false;
    }

    return true;
}
function CheckParameter(hours, mins)
{
    if ((hours.charAt(0) == '-') || (mins.charAt(0) == '-') || (hours.charAt(0) == '+') || (mins.charAt(0) == '+')) {
        AlertEx(GetLanguageDesc('ssmp_rebootdule_type_invalid'));
        return false;
    }

    if (!(isIntegerOrNull(hours) && isIntegerOrNull(mins))) {
        AlertEx(GetLanguageDesc('ssmp_rebootdule_type_invalid'));
        return false;
    }

    if (hours > 23) {
        AlertEx(GetLanguageDesc("ssmp_rebootdule_hour_invalid"));
        return false;
    }

    if ((parseInt(mins) != 30) && (parseInt(mins) != 0)) {
        AlertEx(GetLanguageDesc("ssmp_rebootdule_min_invalid_egypt"));
        return false;
    }

    return true;
}

function Apply()
{
    var enable = getCheckVal('rebootChEnable');
    if (enable == 0) {
      
        return false;
    }

    var curTimeList = "";
    var curDayList = "";
    var count = 1;
    for (var i = 0; i < weekNumArray.length; i++) {
        var curHour = getValue('time_start_hours_' + weekNumArray[i]);
        var curMin = getSelectVal('time_start_min_' + weekNumArray[i]);
        if (curHour == "") {
            continue;
        }

        if (!CheckParameter(curHour, curMin)) {
            return false;
        }

        if (count > 3) {
            AlertEx(GetLanguageDesc("ssmp_rebootdule_times_invalid"));
            return false
        }

        splitpart = (curDayList == "") ? "" : ",";
        curTimeList += splitpart;
        curDayList += splitpart;
        curTimeList += getValue('time_start_hours_' + weekNumArray[i]) + ':' + getValue('time_start_min_' + weekNumArray[i]);
        curDayList += weekNumArray[i];
        count++;
    }

    if (curDayList == "") {
        return false;
    }

    var Form = new webSubmitForm();
    Form.addParameter('x.Enable', 1);
    Form.addParameter('x.RebootStartTime', curTimeList);
    Form.addParameter('x.RepeatDay', curDayList);
    Form.setAction('set.cgi?' + 'x=InternetGatewayDevice.X_HW_AutoRebootByWeek' +
                   '&RequestFile=html/ssmp/scheduledrestart/scheduledrestart_egypt.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function Cancel()
{
    LoadFrame();
}
</script>
</head>

<body class="mainbody" onLoad="LoadFrame();">
<table width="100%" height="5" border="0" cellpadding="0" cellspacing="0"><tr> <td></td></tr></table>
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("rebootSche", GetDescFormArrayById(cfg_rebootdule_language, "ssmp_rebootdule_header"), GetDescFormArrayById(cfg_rebootdule_language, "ssmp_rebootdule_title_egypt"), false);
</script>

<div class="title_spread"></div>

<div class="func_title"><script>document.write(GetLanguageDesc("ssmp_rebootdule_system_time"));</script></div>
<form id="systime">
  <table id="systemtime" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
    <li id="time" RealType="HtmlText" DescRef="ssmp_rebootdule_system_time" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="time" InitValue="Empty" />
    <li id="sync" RealType="HtmlText" DescRef="ssmp_rebootdule_sync_status" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="time" InitValue="Empty" />
  </table>

  <script>
    systimeList = HWGetLiIdListByForm("systime", null);
    var TableClass = new stTableClass("width_per25", "table_right align_left","ltr");
    HWParsePageControlByID("systime", TableClass, cfg_rebootdule_language, null);
  </script>
</form>

<br />

<div class="func_title"><script>document.write(GetLanguageDesc("ssmp_rebootdule_config"));</script></div>

<table width="100%" border="0" cellspacing="0" cellpadding="0" id="rebootScheCfg">
<tr><td>
<form id="ConfigForm" action="../network/set.cgi">
    <table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg">
      <tr id="para_enable">
        <td class="table_title" width="100%">
          <input type='checkbox' id='rebootChEnable' name='rebootChEnable' onClick='rebootSetEnable();' value="OFF">
          <script>document.write(GetLanguageDesc("ssmp_rebootdule_enable"));</script></input>
      </td>
      </tr>
    </table>

    <table id="rebootCtrlTable" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg" style="display:none">
      <tr id="para_header">
        <td class="table_content" width="7%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week"));</script></td>
          </table>
        </td>
        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_mon"));</script></td>
          </table>
        </td>
        
        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_tue"));</script></td>
          </table>
        </td>

        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_wed"));</script></td>
          </table>
        </td>

        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_thu"));</script></td>
          </table>
        </td>

        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_fri"));</script></td>
          </table>
        </td>

        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_sat"));</script></td>
          </table>
        </td>

        <td class="table_content" width="13.1%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_sun"));</script></td>
          </table>
        </td>
      </tr>

      <tr id="para_time1">
        <td class="table_content" width="7%">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_content" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_time"));</script></td>
          </table>
        </td>

        <script>
            for (var i = 0; i < weekNumArray.length; i++) {
              document.write(
                '<td class="table_content" width="13.1%">' +
                '<table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">' +
                '<input type=\'text\' id="time_start_hours_' + weekNumArray[i] + '" name="time_start_hours" style="width: 1.5rem">' +
                GetLanguageDesc("ssmp_rebootdule_time_separator") +
                '<select id="time_start_min_' + weekNumArray[i] + '" name="time_start_min">' +
                '<option value="00">00</option>' +
                '<option value="30">30</option>' +
                '</select>' +
                '</table>' +
                '</td>'
              )
            }
        </script>
      </tr>
    </table>

    <table id="rebootApplyTable" width="100%" border="0" cellpadding="0" cellspacing="0" style="display:none">
      <tr><td>
        <table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
          <tr>
            <td class="table_submit width_per25"></td>
            <td class="table_submit"> 
              <input type="hidden" name="onttoken" id="onttoken" value="<%HW_WEB_GetToken();%>">
              <button id="applyButton" name="applyButton" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Apply();"><script>document.write(GetLanguageDesc("ssmp_rebootdule_apply"));</script></button>
              <button id="cancelButton" name="cancelButton" type="button" class="CancleButtonCss buttonwidth_100px" onClick="Cancel();"><script>document.write(GetLanguageDesc("ssmp_rebootdule_cancel"));</script></button>
            </td>
          </tr>
        </table>
      </td></tr>
    </table>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr ><td class="width_15px"></td></tr>
    </table> 

</form>
</td></tr>
</table>
</body>
</html>
