<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<title>MAC Filter</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html, wifi_acccess_ctrl_language);%>"></script>
<script language="javascript" src="../../bbsp/common/lanuserinfo.asp"></script>
<style type="text/css">

</style>
<script language="JavaScript" type="text/javascript"> 
var selctIndex = -1;
var numpara = "";
var TableName = "MacfilterConfigList";
var macFilterMax = 128;

if( window.location.href.indexOf("?") > 0)
{
    numpara = window.location.href.split("?")[1]; 
}
var enableFilter = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_WIFIInfo.WIFIAccessControl.AccessEnable);%>';
var CfgModeWord ='<%HW_WEB_GetCfgMode();%>';

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
		setObjNoEncodeInnerHtmlValue(b, wifi_acccess_ctrl_language[b.getAttribute("BindText")]);
	}
}

function stMacFilter(domain, MACAddress)
{
    this.domain = domain;
    this.MACAddress = MACAddress;
}

var MacFilter = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_WIFIInfo.WIFIAccessControl.WhiteStaMacList.{i}, StaMac, stMacFilter);%>;

function stBlackListMac(domain, MACAddress)
{
    this.domain = domain;
    this.MACAddress = MACAddress;
}
var staBlackList = <%WEB_GetStaAccessBlackList();%>;
var staBlackListObject = new Array();

function initStaBlackList() {
    for(var i = 0; i < staBlackList.length; i++) {
        var staObj = staBlackList[i];
        staBlackListObject.push(new stBlackListMac("domain"+ i, staObj["StaMac"]));
    }
    staBlackListObject.push(null);
}
initStaBlackList();

function changeButtonState(macFilterEnable) {
    var disableButton = (macFilterEnable == '1') ? 0 : 1;
    setDisable('Newbutton',disableButton);
    setDisable('DeleteButton', disableButton);
    setDisable('btnApply_ex', disableButton);
    setDisable('cancel',disableButton);
    
    var CheckBoxList = document.getElementsByName(TableName+'rml');
    for(var i = 0; i < CheckBoxList.length; i++) {
        var radioRowId = CheckBoxList[i].id;
        setDisable(radioRowId, disableButton);
    }

    var ChkBoxBlackList = document.getElementsByName(BlackListTableName+'rml');
    for(var i = 0; i < ChkBoxBlackList.length; i++) {
        var radioRowId = ChkBoxBlackList[i].id;
        setDisable(radioRowId, disableButton);
    }
}

function OnEnableMacFilter()
{
    var macFilterEnable = (getElById("EnableMacFilter").checked) ? 1 : 0;
    changeButtonState(macFilterEnable);

    $.ajax({
            type : "POST",
            async : false,
            cache : false,
            data : "x.AccessEnable=" + macFilterEnable +"&x.X_HW_Token="+getValue('onttoken'),
            url : "set.cgi?x=InternetGatewayDevice.X_HW_WIFIInfo.WIFIAccessControl&RequestFile=html/amp/wifiaccessctrl/wifiaccessctrl.asp",
            success : function(data) {
            },
            complete: function (XHR, TS) {
                window.location.reload(true);
                XHR=null;
            }
    });
}

function initEnableRadio() {
    changeButtonState(enableFilter)
    var selectedRow = (MacFilter.length == 1) ? 'record_no' : (TableName + '_record_0'); 
    selectLine(selectedRow);
    setDisplay('TableConfigInfo',0);
    getElById("EnableMacFilter").checked = (enableFilter == "1") ? true : false;
}

function LoadFrame()
{
    initEnableRadio();
	loadlanguage();
}

function CheckForm()
{   
    var macAddress = getElement('SourceMACAddress').value;
    
	if (macAddress == '') 
    {
		AlertEx(wifi_acccess_ctrl_language['wifi_macfilterisreq']);
        return false;
    }
    if (isValidMacAddress(macAddress) == false)
    {
        AlertEx(wifi_acccess_ctrl_language['wifi_themac'] + macAddress + wifi_acccess_ctrl_language['wifi_macisinvalid']);
        return false;
    }
    for (var i = 0; i < MacFilter.length-1; i++)
    {
        if (selctIndex != i)
        {
            if (macAddress.toUpperCase() == MacFilter[i].MACAddress.toUpperCase())
            {
                AlertEx(wifi_acccess_ctrl_language['wifi_themac'] + macAddress + wifi_acccess_ctrl_language['wifi_macrepeat']);
                return false;
            }
        }
        else
        {
            continue;
        }
    }
    return true;
}

function addFilterRule(staMac) {
    $.ajax({
            type : "POST",
            async : false,
            cache : false,
            data : "x.StaMac=" + staMac +  "&x.X_HW_Token="+getValue('onttoken'),
            url : "add.cgi?x=InternetGatewayDevice.X_HW_WIFIInfo.WIFIAccessControl.WhiteStaMacList&RequestFile=html/amp/wifiaccessctrl/wifiaccessctrl.asp",
            success : function(data) {
            },
            complete: function (XHR, TS) {
                XHR=null;
                window.location.reload(true);
            }
    });

}

function setFilterRule(staMac) {
    $.ajax({
            type : "POST",
            async : false,
            cache : false,
            data : MacFilter[selctIndex].domain + "=&x.X_HW_Token="+getValue('onttoken'),
            url : "del.cgi?x=InternetGatewayDevice.X_HW_WIFIInfo.WIFIAccessControl.WhiteStaMacList&RequestFile=html/amp/wifiaccessctrl/wifiaccessctrl.asp",
            success : function(data) {
            },
            complete: function (XHR, TS) {
                addFilterRule(staMac);
                XHR=null;
            }
    });
}

function AddSubmitParam(staMac, isSrcBlackList)
{
    if( isSrcBlackList || (selctIndex == -1))
	{
        addFilterRule(staMac);
	}
	else
	{
        setFilterRule(staMac);
	}
    initEnableRadio('0');
}

function SubmitEx()
{
    if (!CheckForm())
	{
		return;
	}
    AddSubmitParam(getValue('SourceMACAddress'), false);
}

function setCtlDisplay(record)
{
    setText('SourceMACAddress', record.MACAddress);
}

function setControl(index)
{   
    var record;
    selctIndex = index;
    if (index == -1)
	{
	    if (MacFilter.length >= macFilterMax + 1) {
            setDisplay('TableConfigInfo', 0);
            AlertEx(wifi_acccess_ctrl_language['wifi_macfilterfull']);
            return;
        }
        else
        {
            record = new stMacFilter('', '');
            setDisplay('TableConfigInfo', 1);
            setCtlDisplay(record);
        }
	}
    else if (index == -2)
    {
        setDisplay('TableConfigInfo', 0);
    }
	else
	{
	    record = MacFilter[index];
        setDisplay('TableConfigInfo', 1);
        setCtlDisplay(record);
	}

    if (enableFilter == "1") {
        setDisable('btnApply_ex',0);
        setDisable('cancel',0);
    }
}

function MacfilterConfigListselectRemoveCnt(val)
{
    
}

function getNumOfWhiteList() {
    var TotalElements = document.getElementsByName(TableName+'rml');
    return (TotalElements == null) ? 0 : TotalElements.length;
}

function BlackListConfiglistselectRemoveCnt(val) {
    if (!val.checked) {
        return;
    }

    if (getNumOfWhiteList() >= macFilterMax) {
        AlertEx(wifi_acccess_ctrl_language['alert_black_list_large_num']);
        return;
    }

    var idx = -1;
    var ChkBoxBlackList = document.getElementsByName(BlackListTableName+'rml');
    for(var i = 0; i < ChkBoxBlackList.length; i++) {
        if (ChkBoxBlackList[i] == val) {
            idx = i;
        }
    }

    var SelectedStaMacAddress = document.getElementById(BlackListTableName + '_'+ idx + '_1');
    if (SelectedStaMacAddress.length == 0) {
        return;
    }
    var StaMacaddress = SelectedStaMacAddress.textContent;
    AddSubmitParam(StaMacaddress, true);
}

function OnDeleteButtonClick(TableID)
{ 
    if ((MacFilter.length-1) == 0)
	{
	    AlertEx(wifi_acccess_ctrl_language['wifi_nomacfilter']);
	    return;
	}

	if (selctIndex == -1)
	{
	    AlertEx(wifi_acccess_ctrl_language['wifi_savemacfilter']);
	    return;
	}

    var CheckBoxList = document.getElementsByName(TableName+'rml');
	var Count = 0;
    var delData = ""
    for (var i = 0; i < CheckBoxList.length; i++)
	{
		if (CheckBoxList[i].checked != true)
		{
			continue;
		}
		
		Count++;
        delData += CheckBoxList[i].value + "=&"
	}
	if (Count <= 0)
	{
		AlertEx(wifi_acccess_ctrl_language['wifi_selectmacfilter']);
		return;
	}

    $.ajax({
            type : "POST",
            async : false,
            cache : false,
            data : delData + "x.X_HW_Token="+getValue('onttoken'),
            url : "del.cgi?x=InternetGatewayDevice.X_HW_WIFIInfo.WIFIAccessControl.WhiteStaMacList&RequestFile=html/amp/wifiaccessctrl/wifiaccessctrl.asp",
            success : function(data) {
            },
            complete: function (XHR, TS) {
                XHR=null;
                window.location.reload(true);
            }
    });

    initEnableRadio('0');

}

function CancelValue()
{   
    if (selctIndex == -1)
    {
        var tableRow = getElement(TableName);

        if (tableRow.rows.length == 1)
        {
        }
        else if (tableRow.rows.length == 2)
        {
		   setDisplay('TableConfigInfo',0);
        }   
        else
        {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine(TableName + '_record_0');
        }
    }
    else
    {
        setText('SourceMACAddress', MacFilter[selctIndex].MACAddress);
    }
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody">
    <script language="JavaScript" type="text/javascript">
        HWCreatePageHeadInfo("macfilter", GetDescFormArrayById(wifi_acccess_ctrl_language, "wifi_mune"), GetDescFormArrayById(wifi_acccess_ctrl_language, "wifi_ctrl_subtitle"), false);
    </script>
    <div class="title_spread"></div>
    <div id="FilterInfo">
        <form id="MacFilterCfg" style="display:block;">
            <table border="0" cellpadding="0" cellspacing="0">
                <tr > 
                    <td class="table_title width_25p" id="EnableMacFilterLabel"></td> 
                    <td class="table_right"  id="Selectmode" >
                    <td class="table_right"><input type="checkbox" value="false" id="EnableMacFilter" onclick="OnEnableMacFilter()"/></td>
                    <td class="table_right width_5p" ></td>
                    <td class="table_right width_70p" ><label id="EnableMacFilterDes"></label></td> 
                </tr> 
            </table>
            <script>
                getElement('EnableMacFilterLabel').innerHTML = wifi_acccess_ctrl_language['enable_wifi_lockdown'];       
                getElement('EnableMacFilterDes').innerHTML = wifi_acccess_ctrl_language['wifi_ctrl_des'];       
            </script>
        </form>

        <div style="margin-top: 10px; font-size:16px">
        <table  width="100%" border="0" cellpadding="0" cellspacing="0" >
            <tr class="table_head" id="ssid_defail">
            <td BindText='sta_whitelist'></td>
            </tr>
        </table>
        </div>
        <script language="JavaScript" type="text/javascript">
            var MacfilterConfiglistInfo = new Array(new stTableTileInfo("Empty", "", "DomainBox"),
                                                    new stTableTileInfo("wifi_sourcemac", "", "MACAddress"), null);
            var ColumnNum = 2;
            var ShowButtonFlag = true;
            var MacfilterTableConfigInfoList = new Array();
            var TableDataInfo = HWcloneObject(MacFilter, 1);
            HWShowTableListByType(1, TableName, ShowButtonFlag, ColumnNum, TableDataInfo, MacfilterConfiglistInfo, wifi_acccess_ctrl_language, null);
        </script>

        <form id="TableConfigInfo" style="display:none;"> 
        <div class="list_table_spread"></div>
            <table border="0" cellpadding="0" cellspacing="1"  width="100%">
                <li id="SourceMACAddress" RealType="TextBox"      DescRef="wifi_sourcemacmh"  RemarkRef="wifi_macfilternote3" ErrorMsgRef="Empty" Require="TRUE"  BindField="x.StaMac" MaxLength='17' InitValue="Empty" />
            </table>
            <script language="JavaScript" type="text/javascript">
                var TableClass = new stTableClass("width_per20", "width_per80", "ltr");
                MacfilterConfigFormList = HWGetLiIdListByForm("TableConfigInfo", null);
                HWParsePageControlByID("TableConfigInfo", TableClass, wifi_acccess_ctrl_language, null);
            </script>

            <table cellpadding="0" cellspacing="0" width="100%" class="table_button"> 
                <tr > 
                    <td class='width_per20'></td> 
                    <td class="table_submit">
                    <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
                    <button id='btnApply_ex' name="btnApply_ex" class="ApplyButtoncss buttonwidth_100px" type="button" onClick="SubmitEx();"><script>document.write(wifi_acccess_ctrl_language['wifi_app']);</script></button> 
                    <button id='Cancel' name="cancel" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelValue();"><script>document.write(wifi_acccess_ctrl_language['wifi_cancel']);</script></button> </td> 
                </tr> 
                <tr> 
                    <td  style="display:none"> <input type='text'> </td> 
                </tr>          
            </table> 
        </form>
        
        <div style="margin-top:50px; font-size:16px">
            <div style="margin-bottom: 5px;">
                <table  width="100%" border="0" cellpadding="0" cellspacing="0" >
                    <tr class="table_head" id="ssid_defail">
                    <td BindText='sta_blacklist'></td>
                    </tr>
                </table>
            </div>
            <script language="JavaScript" type="text/javascript">
                var BlackListConfiglistInfo = new Array(new stTableTileInfo("cancel_sta_block", "", "DomainBox"),
                                                        new stTableTileInfo("wifi_sourcemac", "", "MACAddress"), null);
                var BlackListTableName = "BlackListConfiglist"
                var BlackListTableConfigInfoList = new Array();
                var TableDataInfo = HWcloneObject(staBlackListObject, 1);
                HWShowTableListByType(1, BlackListTableName, false, ColumnNum, TableDataInfo, BlackListConfiglistInfo, wifi_acccess_ctrl_language, null);
            </script>
        </div>
    </div>
</body>
</html>
