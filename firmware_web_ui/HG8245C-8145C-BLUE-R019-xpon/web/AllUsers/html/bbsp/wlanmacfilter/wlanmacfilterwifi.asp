<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>WLAN MAC Filter</title>
<script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="Javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>
<script language="javascript" src="../common/topoinfo.asp"></script>
<style type="text/css">
.tabnoline td
{
   border:0px;
}
</style>
<script language="JavaScript" type="text/javascript"> 
var selctIndex = -1;
var numpara = "";
var portid  = "";
var TableName = "WMacfilterConfigList";
var WifiMacNum = 28;
var DoubleFreqFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';    
if( window.location.href.indexOf("?") > 0)
{
    numpara = window.location.href.split("?")[1]; 
    portid  = window.location.href.split("?")[2];
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
		b.innerHTML = wlanmacfil_language[b.getAttribute("BindText")];
	}
}

function stMacAllow(domain, macAllow)
{
    this.domain = domain;
    this.macAllow = macAllow;
}

var enableFilter = '0';
var macAllows = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.1,MACAddressControlEnabled,stMacAllow);%>;
if (2 == macAllows.length)
{
    enableFilter = macAllows[0].macAllow;
}

var MacFilter = new Array();
var macAddress = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.AllowedMACAddresses);%>';
var MacFilterSrc = macAddress.split(",");
if (macAddress != "")
{
    MacFilterSrc = macAddress.split(",")
    for (var i = 0; i < MacFilterSrc.length; i++)
    {
        var j = new Object;
        j.domain = i;
        j.MACAddress = MacFilterSrc[i];
		MacFilter.push(j); 
    }
}
MacFilter.push(null);

function LoadFrame()
{
   if (enableFilter != '')
   {    
       setDisplay('FilterInfo',1);
       if (MacFilter.length - 1 == 0)
       {
           selectLine('record_no');
           setDisplay('TableConfigInfo',0);
       }
       else
       {
           selectLine(TableName + '_record_0');
           setDisplay('TableConfigInfo',1);
       }
       setDisable('EnableMacFilter',0);
       setDisable('btnApply_ex',0);
       setDisable('cancel',0);
   }
   else
   {
       setDisplay('FilterInfo',0);
   }
   
   if (enableFilter == "1")
   {
       getElById("EnableMacFilter").checked = true;
   }

	if(isValidMacAddress(numpara) == true)
	{
		clickAdd(TableName + '_head');
		setText('SourceMACAddress', numpara);
	}

	loadlanguage();
}

function SubmitForm()
{
	var WMacfilterRightSpecCfgParaList = new Array();
	var Enable = getElById("EnableMacFilter").checked;
	if (Enable == true)
	{
	   WMacfilterRightSpecCfgParaList.push(new stSpecParaArray("x.MACAddressControlEnabled", 1, 1));
	}
	else
	{
	   WMacfilterRightSpecCfgParaList.push(new stSpecParaArray("x.MACAddressControlEnabled", 0, 1));
	}
    var Parameter = {};
	Parameter.asynflag = null;
	Parameter.FormLiList = WMacfilterInfoConfigFormList;
	Parameter.SpecParaPair = WMacfilterRightSpecCfgParaList;
	var tokenvalue = getValue('onttoken');
	var url = 'set.cgi?x=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1'
				+ '&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilterwifi.asp';
				
	HWSetAction(null, url, Parameter, tokenvalue);	
}

function CheckForm()
{   
    var macAddress = getElement('SourceMACAddress').value;

    if (macAddress == '') 
    {
		AlertEx(wlanmacfil_language['bbsp_macfilterisreq']);
        return false;
    }
    if (macAddress != '' && isValidMacAddress1(macAddress) == false ) 
    {
		AlertEx(wlanmacfil_language['bbsp_themac'] + macAddress + macfilter_language['bbsp_macisinvalid']);       
        return false;
    }
	
	for (var i = 0; i < MacFilter.length-1; i++)
    {
        if (selctIndex != i)
        {
            if (macAddress.toUpperCase() == MacFilter[i].MACAddress.toUpperCase())
            {
                AlertEx(macfilter_language['bbsp_themac'] + macAddress + macfilter_language['bbsp_macrepeat']);
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

function AddSubmitParam()
{
	if (false == CheckForm())
	{
		return;
	}

    setDisable('EnableMacFilter',1);
    setDisable('btnApply_ex',1);
    setDisable('cancel',1);

	var Onttoken = getValue('onttoken');
    var stMacAddress = '';
    var WMacfilterList = new Array();
    var Parameter = {};
    
    for (var i = 0; i < MacFilter.length - 1; i++)
    {
        if (((selctIndex >= 0) && (selctIndex != i)) ||
            (-1 == selctIndex))
        {
        	stMacAddress += MacFilter[i].MACAddress;

            stMacAddress += ',';
        }
    }
    stMacAddress += getValue('SourceMACAddress');
    
    WMacfilterList.push(new stSpecParaArray("x.AllowedMACAddresses", stMacAddress, 1),
                        new stSpecParaArray("x.MACAddressControlEnabled", 0, 2));  
    
	Parameter.asynflag = null;
	Parameter.FormLiList = WMacfilterInfoConfigFormList;
	Parameter.SpecParaPair = WMacfilterList;
	var tokenvalue = getValue('onttoken');
	var url = 'set.cgi?x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement'
				+ '&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilterwifi.asp';				
	HWSetAction(null, url, Parameter, tokenvalue);	
    
    return;
}

function setCtlDisplay(record)
{
	if (record == null)
	{
		setText('SourceMACAddress','');
	}
	else
	{
        setText('SourceMACAddress', record.MACAddress);
	}	
}

function setMacInfo()
{
    setDisplay("MacAlert",1);
    AlertEx(wlanmacfil_language['bbsp_rednote']);
}

function DeleteLastLineRow()
{
    var tableRow = getElementById(TableName);
    if (tableRow.rows.length > 2)
    {
        tableRow.deleteRow(tableRow.rows.length-1);
    }
    return false;
}

function setControl(index)
{   
    var record;
    selctIndex = index;
    if (index == -1)
	{
	    if (MacFilter.length >= (WifiMacNum+1))
        {
            DeleteLastLineRow();
            setDisplay('TableConfigInfo', 0);
			AlertEx(wlanmacfil_language['bbsp_rulenum3']);
            return;
        }
        else
        {
            setDisplay('TableConfigInfo', 1);
			setMacInfo();
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
    setDisable('btnApply_ex',0);
    setDisable('cancel',0);
}

function OnDeleteButtonClick(TableID)
{ 
    if ((MacFilter.length-1) == 0)
	{
	    AlertEx(wlanmacfil_language['bbsp_nonerulealert']);
	    return;
	}

	if (selctIndex == -1)
	{
	    AlertEx(wlanmacfil_language['bbsp_saverulealert']);
	    return;
	}

    var CheckBoxList = document.getElementsByName(TableName+'rml');
    var Form = new webSubmitForm();
	var Count = 0;
    var macaddress = '';
    for (var i = 0; i < CheckBoxList.length; i++)
	{
		if (CheckBoxList[i].checked != true)
		{
		    macaddress += MacFilter[i].MACAddress;
            macaddress += ',';
			continue;
		}
		
		Count++;

	}
    if (Count <= 0)
	{
		AlertEx(wlanmacfil_language['bbsp_chooserulealert']);
		return;
	}

    if (enableFilter == 1)
    {   
        if(ConfirmEx(wlanmacfil_language['bbsp_whitealert']))
        {
            setDisable('btnApply_ex',1);
            setDisable('cancel',1);
			Form.addParameter('x.AllowedMACAddresses', macaddress.substring(0, macaddress.length-1));
            Form.addParameter('x.X_HW_Token', getValue('onttoken'));
			Form.setAction('set.cgi?' +'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement' + '&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilterwifi.asp');
			Form.submit();
        }
        else
        {
            return;
        }
    }
    else
    {
        if (ConfirmEx(wlanmacfil_language['bbsp_deletealert']) == false)
    	{
			document.getElementById("DeleteButton").disabled = false;
			return;
        }

        setDisable('btnApply_ex',1);
        setDisable('cancel',1);
        Form.addParameter('x.AllowedMACAddresses', macaddress.substring(0, macaddress.length-1));
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));
		Form.setAction('set.cgi?' +'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement' + '&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilterwifi.asp');
		Form.submit(); 
    }  
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
        setText('SourceMACAddress',MacFilter[selctIndex].MACAddress);
    }
}

function WMacfilterConfigListselectRemoveCnt()
{

}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("wlanmacfilter", GetDescFormArrayById(wlanmacfil_language, "bbsp_mune"), GetDescFormArrayById(wlanmacfil_language, "bbsp_wlanmac_title"), false);
</script> 
<div class="title_spread"></div>

<div id="FilterInfo">
<form id="MacFilterCfg" style="display:block;">
	<table border="0" cellpadding="0" cellspacing="1"  width="100%"> 
		<li   id="EnableMacFilter" RealType="CheckBox" DescRef="bbsp_filterenable1" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE"   BindField="x.MACAddressControlEnabled"   InitValue="Empty" ClickFuncApp="onclick=SubmitForm"/>
	</table>
	<script>
		var TableClass = new stTableClass("width_per30", "width_per70", "ltr");
		WMacfilterInfoConfigFormList = HWGetLiIdListByForm("MacFilterCfg", null);
		HWParsePageControlByID("MacFilterCfg", TableClass, wlanmacfil_language, null);
		getElById("EnableMacFilter").title = wlanmacfil_language['bbsp_macfilternote1'];
	</script>
</form>
<div class="func_spread"></div>

<script language="JavaScript" type="text/javascript">
	var WMacfilterConfiglistInfo = new Array(new stTableTileInfo("Empty","align_center","DomainBox"),									
								   new stTableTileInfo("bbsp_macaddr","align_center","MACAddress"),null);	
	var ColumnNum = 2;
	var ShowButtonFlag = true;
	var WMacfilterTableConfigInfoList = new Array();
	var TableDataInfo = HWcloneObject(MacFilter, 1);
	HWShowTableListByType(1, TableName, ShowButtonFlag, ColumnNum, TableDataInfo, WMacfilterConfiglistInfo, wlanmacfil_language, null);
</script>

<div class="list_table_spread"></div>
<form id="TableConfigInfo" style="display:none;"> 
	<table border="0" cellpadding="0" cellspacing="1"  width="100%"> 
		<li   id="SourceMACAddress" RealType="TextBox" DescRef="bbsp_macaddrtitle" RemarkRef="bbsp_macfilternote3" ErrorMsgRef="Empty" Require="TRUE" BindField="x.AllowedMACAddresses"  InitValue="Empty" MaxLength='17'/>
	</table>
	<script language="JavaScript" type="text/javascript">
		TableClass = new stTableClass("width_per20", "width_per80", "ltr");
		WMacfilterConfigFormList = HWGetLiIdListByForm("TableConfigInfo", null);
		HWParsePageControlByID("TableConfigInfo", TableClass, wlanmacfil_language, null);
	</script>
	<div id="MacAlert" style="display:none;"> 
		<table cellpadding="2" cellspacing="0" class="pm_tabal_bg" width="100%"> 
		  <tr> 
			<td class='color_red' BindText='bbsp_rednote'></td> 
		  </tr> 
		</table> 
	 </div>
	 <table cellpadding="0" cellspacing="0" width="100%" class="table_button"> 
          <tr>
            <td class='width_per20'></td> 
            <td class="table_submit">
			  <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
			  <button id='btnApply_ex' name="btnApply_ex" class="ApplyButtoncss buttonwidth_100px" type="button" onClick="AddSubmitParam();"> <script>document.write(wlanmacfil_language['bbsp_apply']);</script> </button> 
              <button id='Cancel' name="cancel" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelValue();"/> <script>document.write(wlanmacfil_language['bbsp_cancle']);</script> </button></td> 
          </tr> 
		  <tr> 
			  <td  style="display:none"> <input type='text'> </td> 
		  </tr>
      </table> 
</form>
</div>
</body>
</html>
