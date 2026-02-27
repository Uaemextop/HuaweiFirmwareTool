
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<title>Automatic Reboot</title>
<script language="JavaScript" type="text/javascript">

function GetLanguageDesc(Name)
{
    return cfg_rebootdule_language[Name];
}

function stDuration(domain, ForceActive, Time, Day, ForceFlow)
{
    this.domain = domain;
    this.ForceActive = ForceActive;
    this.Time = Time;
    this.Day = Day;
    this.ForceFlow = ForceFlow;
}

var curLanguage='<%HW_WEB_GetCurrentLanguage();%>';
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var DurationArr = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.AutoResetConfig, ForceActive|Time|Day|ForceFlow, stDuration);%>;

function stApDevice(domain, type, sn, GhnMacAddr, APMacAddr, ApOnlineFlag)
{
    this.domain = domain;
    this.type = type;
    this.sn = sn;
	this.GhnMacAddr = GhnMacAddr.toUpperCase();
    this.APMacAddr = APMacAddr;
    this.ApOnlineFlag = ApOnlineFlag;
    
}

var apDeviceList = new Array();
apDeviceList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}, DeviceType|SerialNumber|GhnMacAddr|APMacAddr|ApOnlineFlag, stApDevice);%>;
apDeviceList = apDeviceList.filter(function(item){
    return item && item.ApOnlineFlag == '1';
});

function userDeviceInfo(Domain,MACAddress,Name,LastStatusChangeTime) {
    this.Domain = Domain;
    this.MACAddress = MACAddress.toUpperCase();
    this.Name = Name;
    this.LastStatusChangeTime = LastStatusChangeTime;
}

var allUserDevinfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_HOMENET_NAME.hosts.{i},MACAddress|Name|LastStatusChangeTime ,userDeviceInfo);%>;

var curAp ='<%WEB_GetApRebootByWeek();%>'; 
if (curAp.length > 0) {
    curAp = curAp.split(';');
    curAp = curAp.map(function(item){
        var itemArr = item.split('|');
        var res = {};
        itemArr.map(function(attr){
            var attrArr = attr.split('=');
            res[attrArr[0]] = attrArr[1];
        })
        return res;
    });

    curAp = curAp.map(function(item){
        var temp = apDeviceList.filter(function(e){
            if (e && (e.APMacAddr == item.mac)){
                return true
            }
        })

        if (temp.length > 0) {
            item.type = temp[0].type
        }

        item.alias = item.type;
        for (var index = 0; index < allUserDevinfo.length; index++) {
            var dev = allUserDevinfo[index];
            if(dev && (dev.Name != "") && (item.mac == dev.MACAddress)) {
                item.alias = dev.Name;
                break;
            }
        }

        return item;
    });
}

function GetDurationIndex(DurationDomain)
{
    var index = 0;
    index = DurationDomain.indexOf('.Duration.', 0);
    index += '.Duration.'.length;
    return DurationDomain.substr(index, index+1);
}

function rebootTimeSplit(strTimeStart)
{
    var i = strTimeStart.indexOf(':', 0);
    if (i != 0)
    {
        setText('time_start_hour', strTimeStart.substr(0, i));
        setText('time_start_min', strTimeStart.substr(i + 1));
    }
}

var myStrArray = new Array("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday");
var myNumArray = new Array("1", "2", "3", "4", "5", "6", "7");
var APTableName = 'APrebootTable';

function rebootRepeatSplit(strValue)
{
    var i = 0;

    if (strValue == '')
    {
        return;
    }

    for (i = 0; i < 7; i++) {
        strValue = strValue.replace(myStrArray[i], myNumArray[i]);
    }

    for (i = 1; i <= 7; i++)
    {
        var CheckID = 'repeat_day' + + i;
        setCheck(CheckID, 0);
    }

    for (i = 0; i < strValue.length; i = i + 2)
    {
        var CheckID = 'repeat_day' + + strValue.charAt(i);
        setCheck(CheckID, 1);
    }
}

function LoadResource()
{
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length ; i++) 
    {
        var b = all[i];
        if(b.getAttribute("BindText") == null)
        {
            continue;
        }

        if (cfg_rebootdule_language[b.getAttribute("BindText")]) 
        {
            b.innerHTML = cfg_rebootdule_language[b.getAttribute("BindText")];
        }
    }
}

function LoadFrame()
{
    var rebootEnable = <%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.AutoResetConfig.Enable);%>;
    setCheck('rebootChEnable', rebootEnable);

    setDisplay('rebootCtrlTable',rebootEnable);
    setDisplay('rebootApplyTable',rebootEnable);

    if (rebootEnable == 1)
    {
        rebootTimeSplit(DurationArr[0].Time);
        rebootRepeatSplit(DurationArr[0].Day);
    }  
}

function rebootSetEnable()
{
    var Form = new webSubmitForm();
    var enable = getCheckVal('rebootChEnable');

    setDisplay('rebootCtrlTable',enable);
    setDisplay('rebootApplyTable',enable);

    Form.addParameter('x.Enable',enable);
    Form.setAction('set.cgi?x=InternetGatewayDevice.LANDevice.1.AutoResetConfig'
                    + '&RequestFile=html/ssmp/scheduledrestart/Scheduledrestart.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function APrebootTableselectRemoveCnt(element)
{
}

function isIntegerOrNull(value)
{
    if ((true != isPlusInteger(value)) && ('' != value))
    {
        return false;
    }
    
    return true;
}
function setParameterTimeCheck(Form)
{
    var time1_begin_h = getValue('time_start_hour');
    
    var time1_begin_m = getValue('time_start_min');

    if ((time1_begin_h.charAt(0) == '-') ||
        (time1_begin_m.charAt(0) == '-') ||
        (time1_begin_h.charAt(0) == '+') ||
        (time1_begin_m.charAt(0) == '+'))
    {
        AlertEx(GetLanguageDesc('ssmp_rebootdule_type_invalid'));
        return false;
    }

    if (!(isIntegerOrNull(time1_begin_h) && isIntegerOrNull(time1_begin_m)))
    {
        AlertEx(GetLanguageDesc('ssmp_rebootdule_type_invalid'));
        return false;
    }

    if ((time1_begin_h == '') || (time1_begin_m == ''))
    {
        if ((time1_begin_h != '') || (time1_begin_m != ''))
        {
            AlertEx(ssmp_rebootdule_time_empty("ssmp_rebootdule_time_empty"));
            return false;
        }
    }

    if ((time1_begin_h == '') && (time1_begin_m == ''))
    {
        time1_begin_h = 0;
        time1_begin_m = 0;
        time1_end_h = 0;
        time1_end_m = 0;
    }

    if (time1_begin_h > 23)
    {
        AlertEx(GetLanguageDesc("ssmp_rebootdule_hour_invalid"));
        return false;
    }

    if (time1_begin_m > 59)
    {
        AlertEx(GetLanguageDesc("ssmp_rebootdule_min_invalid"));
        return false;
    }

    return true;
}

function repeatdayformat(repeatday)
{
    if (getCheckVal(repeatday) == 1)
    {
        var length = repeatday.length;
        var str = parseInt(repeatday.charAt(length-1));
        return str + ',';
    }

    return '';
}

function droplastsplitRepeatDay(time_repeat)
{
    var length = time_repeat.length; 
    if (length > 0)
    {
        return time_repeat.substr(0,length-1);
    }

    return '';
}

function droplastsplitTime(time_value)
{
    if (time_value ==  ':')
    {
        return '';
    }

    return time_value;
}

function Apply()
{
    var Form = new webSubmitForm();
    var enable = getCheckVal('rebootChEnable');
    if (setParameterTimeCheck(Form) == false)
    {
        return false;
    }

    var time1_start = getValue('time_start_hour') + ':' + getValue('time_start_min');
    var time1_repeat = repeatdayformat('repeat_day1') + repeatdayformat('repeat_day2') + repeatdayformat('repeat_day3') + repeatdayformat('repeat_day4') 
                       + repeatdayformat('repeat_day5') + repeatdayformat('repeat_day6') + repeatdayformat('repeat_day7');
    time1_repeat = droplastsplitRepeatDay(time1_repeat);
    time1_start = droplastsplitTime(time1_start);
    
    if (time1_repeat == '')
    {
        AlertEx(GetLanguageDesc("ssmp_rebootdule_week_empty"));
        return false;
    }

    for (var i = 0; i < 7; i++) {
        time1_repeat = time1_repeat.replace(myNumArray[i], myStrArray[i]);
    }

    Form.addParameter('x.Time', time1_start);
    Form.addParameter('x.Day', time1_repeat);

    Form.setAction('set.cgi?' 
                    + 'x=' + 'InternetGatewayDevice.LANDevice.1.AutoResetConfig'
                    + '&RequestFile=html/ssmp/scheduledrestart/Scheduledrestart.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function Cancel()
{
    LoadFrame();
}

function ApplyAP(id){
    setDisable(id, 1);
    var idToArr = id.split('_');
    var devIndex = idToArr[idToArr.length - 1];
	var time1_start = getValue('time_start_hour' + devIndex) + ':' + getValue('time_start_min' + devIndex);
	var time1_repeat = repeatdayformat('repeat_day' + devIndex + '_' + '1') + repeatdayformat('repeat_day' + devIndex + '_' + '2') + repeatdayformat('repeat_day' + devIndex + '_' + '3') + repeatdayformat('repeat_day' + devIndex + '_' + '4') 
                   + repeatdayformat('repeat_day' + devIndex + '_' + '5') + repeatdayformat('repeat_day' + devIndex + '_' + '6') + repeatdayformat('repeat_day' + devIndex + '_' + '7');

    time1_repeat = droplastsplitRepeatDay(time1_repeat);
    time1_start = droplastsplitTime(time1_start);
	if (time1_repeat == '') {
        AlertEx(GetLanguageDesc("ssmp_rebootdule_week_empty"));
        setDisable(id, 0);
        return false;
    }
	
	for (var i = 0; i < 7; i++) {
        time1_repeat = time1_repeat.replace(myNumArray[i], myStrArray[i]);
    }
	
	var APMacAddr = document.getElementById(APTableName + '_' + devIndex + '_' + '4');
	var submitParaInfo = 'mac=' + APMacAddr.innerText;
	submitParaInfo += '&startTime=' + time1_start;
	submitParaInfo += '&repeatDay=' + time1_repeat;
	submitParaInfo += '&enable=' + getCheckVal('APrebootTable_rml' + devIndex);;
	submitParaInfo += '&forceActive=' + '1';
	submitParaInfo += '&forceFlow=' + '10';
	
	$.ajax({
	type : "POST",
	async : false,
	cache : false,
	data : submitParaInfo + "&x.X_HW_Token=" + getValue('onttoken'),
	url : 'SetApRebootConfig.cgi?'
		+ 'RequestFile=html/ssmp/scheduledrestart/Scheduledrestart.asp',
	success : function(data) {
        location.reload();
	},
    error : function(err) {
        setDisable(id, 0);
        window.location = '../../proerrcode.asp';
    }
})
}

function CancelAP(id) {
    location.reload();
}

function setControl(index, id) {
}

</script>

<style>
    .max-width{
        max-width: 53px;
        word-wrap: break-word;
        text-align: center;
    }
    .vertical-align{
        vertical-align: middle;
    }
    .flex{
        display: flex;
        justify-content: center;
        align-items:stretch;
    }
    .bolck{
        display: block;
    }
</style>
</head>

<body class="mainbody" onLoad="LoadFrame();">
<table width="100%" height="5" border="0" cellpadding="0" cellspacing="0"><tr> <td></td></tr></table>  
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("rebootSche", GetDescFormArrayById(cfg_rebootdule_language, "ssmp_rebootdule_header"), GetDescFormArrayById(cfg_rebootdule_language, "ssmp_rebootdule_title"), false);
</script>

<div class="title_spread"></div>

<div class="func_title"><SCRIPT>document.write(GetLanguageDesc("ssmp_rebootdule_config"));</SCRIPT></div>

<table width="100%" border="0" cellspacing="0" cellpadding="0" id="rebootScheCfg">
<tr><td>
<form id="ConfigForm" action="../network/set.cgi">
    <table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg">
        <tr id="para_enable">
            <td class="table_title" width="100%"><input type='checkbox' id='rebootChEnable' name='rebootChEnable' onClick='rebootSetEnable();' value="OFF">
            <script>document.write(GetLanguageDesc("ssmp_rebootdule_enable"));</script></input></td>
        </tr>
    </table>

    <table id="rebootCtrlTable" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg" style="display:none">
        <tr id="para_header">
          <td class="table_title" width="15%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_time_start"));</script></td>
            </table>
          </td>
          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_mon"));</script></td>
            </table>
          </td>
          
          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">          
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_tue"));</script></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">          
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_wed"));</script></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_thu"));</script></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_fri"));</script></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_sat"));</script></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><script>document.write(GetLanguageDesc("ssmp_rebootdule_week_sun"));</script></td>  
            </table>
          </td>
        </tr>

        <tr id="para_time1">
          <td class="table_title" width="17%">
            <input type='text' id="time_start_hour" name="time_start_hour" style="width: 1rem" maxlength="2">
           <script>document.write(GetLanguageDesc("ssmp_rebootdule_time_separator"));</script>
            <input type='text' id="time_start_min" name="time_start_min" style="width: 1rem" maxlength="2">
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day1' name='repeat_day1'  value="OFF"></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day2' name='repeat_day2'  value="OFF"></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day3' name='repeat_day3'  value="OFF"></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day4' name='repeat_day4'  value="OFF"></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day5' name='repeat_day5'  value="OFF"></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day6' name='repeat_day6'  value="OFF"></td>
            </table>
          </td>

          <td class="table_title" width="12%">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
            <td class="table_title" width="100%"><input type='checkbox' id='repeat_day7' name='repeat_day7'  value="OFF"></td>
            </table>
          </td>
        </tr>
    </table>

    <table id="rebootApplyTable" width="100%" border="0" cellpadding="0" cellspacing="0" style="display:none">
      <tr><td>
        <table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
          <tr>
            <td class="table_submit width_per25"></td>
            <td class="table_submit"> 
              <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
              <button id="applyButton" name="applyButton" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Apply();"><script>document.write(GetLanguageDesc("ssmp_rebootdule_apply"));</script></button>
              <button id="cancelButton" name="cancelButton" type="button" class="CancleButtonCss buttonwidth_100px" onClick="Cancel();"><script>document.write(GetLanguageDesc("ssmp_rebootdule_cancel"));</script></button>
            </td>
          </tr>
        </table>
      </td></tr>
    </table>
 
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr ><td class="width_15px height15p"></td></tr>
    </table> 

    <div class="func_title">
        <script>
            if (curAp.length > 0) {
                document.write(GetLanguageDesc("ssmp_rebootdule_config_AP"));
            }
        </script>
    </div>
    
    <script>
       if(curAp.length > 0){
            var ColumnNum = 8;
            var showWeek = function(day, index){
                var dayArr = day.split(',')
                var res = '<table width="100%" style="border-collapse:collapse; border-spacing:0px -2px;">';
                var dayHtml ='<tr>';
                var checkboxHtml = '<tr>';
                var html = "";
                myStrArray.forEach(function(item, i){
                    var checked = ""
                    if (dayArr.indexOf(item) > -1){
                        checked = "checked";
                    }
                    html = '<tr><td>';
                    html += GetLanguageDesc("ssmp_rebootdule_week_" + item.substr(0,3).toLocaleLowerCase());
                    html +='</td>';
                    html += '<td>';
                    html += '<input type="checkbox" id="repeat_day' + index + '_' +  (i + 1) + '" name="repeat_day' + index + '_' + (i + 1) + '"  value="OFF"'+ checked + '>';
                    html +='</td><tr>';
                res += html;

                })
                return res + '</table>';
                
            }; 
            var showTime = function(time, index){
                var timeTemp = time.split(':');
                var res ='';
                var timeStart = '<input type="text" id="time_start_hour' + index +'" style="width: 1rem" maxlength="2" value="' + timeTemp[0] + '">';
                var timeEnd = '<input type="text" id="time_start_min' + index +'" style="width: 1rem" maxlength="2" value="' + timeTemp[1] + '">';
                res = res + timeStart + GetLanguageDesc("ssmp_rebootdule_time_separator")  + timeEnd;
                return res;
            };
            var operationButton = function(index){
                var res = '';
                var applyButtonHtml = '<div class=""><button type="button" id="' + APTableName + "ApplyButton_" + index + '" class=" bolck ApplyButtoncss buttonwidth_100px" onClick="ApplyAP(this.id)">'
                    applyButtonHtml += GetLanguageDesc("ssmp_rebootdule_apply");
                    applyButtonHtml += '</button></div>'

                var cancelButtonHtml = '<div class=""><button type="button" id="' + APTableName + "CancleButton_" + index + '" class="bolck ApplyButtoncss buttonwidth_100px" onClick="CancelAP(this.id)">'
                    cancelButtonHtml += GetLanguageDesc("ssmp_rebootdule_cancel");
                    cancelButtonHtml += '</button></div>'

                return res + applyButtonHtml + '</br>' + cancelButtonHtml;
            }
            var TableDataInfo = HWcloneObject(curAp,1)
            TableDataInfo = TableDataInfo.map(function(item,i){
                var weekCol = showWeek(item.repeatDay, i);
                var timeCOl = showTime(item.startTime, i);
                var operation = operationButton(i);

                item.weekCol = weekCol;
                item.timeCOl = timeCOl;
                item.operation = operation;
                return item
            })
            TableDataInfo.push(null)
            var ColumnTitleDesArray = new Array(new stTableTileInfo("Empty", "table_title align_center", "NumIndexBox", false),
                                                    new stTableTileInfo("ssmp_rebootdule_enable", "table_title max-width ", "DomainBox", false),
                                                    new stTableTileInfo("ssmp_rebootdule_name", "table_title max-width ", "type", false),
                                                    new stTableTileInfo("ssmp_rebootdule_alias", "table_title max-width", "alias", false),
                                                    new stTableTileInfo("ssmp_rebootdule_MAC", "table_title align_center", "mac", false), 
                                                    new stTableTileInfo("ssmp_rebootdule_time_start", "table_title align_center", "timeCOl", false, "", 0), 
                                                    new stTableTileInfo("ssmp_rebootdule_day", "table_title align_center", "weekCol", false, "", 0),
                                                    new stTableTileInfo("ssmp_rebootdule_operation", "table_title align_center vertical-align ", "operation", false, "", 0),null);

            HWShowTableListByType(1, APTableName, false, ColumnNum, TableDataInfo, ColumnTitleDesArray,cfg_rebootdule_language, null);
            TableDataInfo.map(function(item,index){
                if(item && item.enable == '1'){
                    setCheck('APrebootTable_rml' + index,1)
                }
            })
       }
        
    </script>
</form>
</td></tr>
</table>
</body>
</html>
