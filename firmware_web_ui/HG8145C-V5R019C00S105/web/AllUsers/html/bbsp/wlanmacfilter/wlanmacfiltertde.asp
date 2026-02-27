<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>MAC Filter</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="Javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>
<script language="javascript" src="../common/topoinfo.asp"></script>
<style>
.width_per39 {
	width: 39%;
}
.width_per61 {
	width: 61%;
}
.tabal_noborder_bg {
	padding:0px 0px 10px 0px;
	background-color: #FAFAFA;
}
.Selectmacaddr{
	width: 160px;
}
</style>
<script language="JavaScript" type="text/javascript"> 
var para = "";
var parassid = "";
var CurSSIDName = 'SSID-1';
if( window.location.href.indexOf("?") > 0)
{
	if (window.location.href.indexOf("SSID") != -1)
	{
		para = window.location.href.split("?"); 
		para = para[para.length -1];
		parassid = para.split("&")[0];
		CurSSIDName = parassid.split("=")[1];
	}
}

var enableFilter = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Security.WlanMacFilterRight);%>';
var Mode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Security.WlanMacFilterPolicy);%>';
var DoubleFreqFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
var SSIDnum = 8;
var TopoInfo = GetTopoInfo();
var selctIndex = -1;
var PreIdx = -1;

function stMacFilter(domain,SSIDName,MACAddress)
{
   this.domain = domain;   
   this.SSIDName = SSIDName;
   this.MACAddress = MACAddress; 
}

var MacFilterSrc = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_GeWlanMacFilter, InternetGatewayDevice.X_HW_Security.WLANMacFilter.{i},SSIDName|SourceMACAddress,stMacFilter);%>;
var MacFilter = new Array();
for (var i = 0; i < MacFilterSrc.length-1; i++)
{
	if (MacFilterSrc[i].SSIDName == CurSSIDName)
	{
		var SSIDIndex = MacFilterSrc[i].SSIDName.charAt(MacFilterSrc[i].SSIDName.length - 1);
		if(IsVisibleSSID('SSID' + SSIDIndex) == true)
		{
			MacFilter.push(MacFilterSrc[i]);
		}
	}
}
MacFilter.push(null);
var MacFilterNr = MacFilter.length - 1;

function setBtnDisable()
{
	setDisable('btnAdd',1);
    setDisable('EnableMacFilter',1);
	setDisable('applybtn',1);
    setDisable('delmaclistall',1);
}

function setMacFilterPolicy()
{
	if (Mode != 1)
	{
		 $.ajax({
		 type : "POST",
		 async : false,
		 cache : false,
		 data : "x.WlanMacFilterPolicy=1"+"&x.X_HW_Token="+getValue('onttoken'),
		 url : "set.cgi?x=InternetGatewayDevice.X_HW_Security&RequestFile=html/not_find_file.asp",
		 success : function(data) {
		 },
		 complete: function (XHR, TS) {
			XHR=null;
		 }
		});
	}
	if (ConfirmEx(wlanmacfil_language['bbsp_rednote']) == false)
	{
		return false;
	}
	return true;
}
function SetFilterEnable()
{
	var Enable = '';
	if (1 == enableFilter)
	{
	   Enable = 0;
	}
	else
	{
	   Enable = 1;
	}
	 $.ajax({
     type : "POST",
     async : false,
     cache : false,
     data : "x.WlanMacFilterRight="+Enable +"&x.X_HW_Token="+getValue('onttoken'),
     url : "set.cgi?x=InternetGatewayDevice.X_HW_Security&RequestFile=html/not_find_file.asp",
     success : function(data) {
     },
     complete: function (XHR, TS) {
        XHR=null;
     }
    });
	setBtnDisable();
	window.location='/html/bbsp/wlanmacfilter/wlanmacfiltertde.asp'+'?SSID='+CurSSIDName; 
}

function CheckAddForm(macAddress)
{   
    var SSIDName = CurSSIDName;    
    var num=0;

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
	if (MacFilter.length >= (TopoInfo.SSIDNum*SSIDnum)+1)
	{
		if(DoubleFreqFlag == 1)
		{
			AlertEx(wlanmacfil_language['bbsp_rulenum2']);
		}
		else
		{
			AlertEx(wlanmacfil_language['bbsp_rulenum1']);
		}
		return;
	}
	
	for (var i = 0; i < MacFilter.length-1; i++)
    {
		if ((macAddress.toUpperCase() == MacFilter[i].MACAddress.toUpperCase()) && (SSIDName == MacFilter[i].SSIDName))
		{
			AlertEx(macfilter_language['bbsp_themac'] + macAddress + macfilter_language['bbsp_macrepeat']);
			return false;
		}
		if (SSIDName == MacFilter[i].SSIDName)
		{
		   num++;
		}
    }
    if (num >= SSIDnum)
    {
        AlertEx(wlanmacfil_language['bbsp_rulenum']);
        return;
    }

    return true;
}

function CheckEditForm(macfilterlist,flag)
{   
    var SSIDName = CurSSIDName;    
	var listLen = macfilterlist.length;

	for (var i = 0; i < listLen; i++)
	{
		var macAddress = macfilterlist[i];
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
		if (listLen >= (TopoInfo.SSIDNum*SSIDnum)+1)
		{
			if(DoubleFreqFlag == 1)
			{
				AlertEx(wlanmacfil_language['bbsp_rulenum2']);
			}
			else
			{
				AlertEx(wlanmacfil_language['bbsp_rulenum1']);
			}
			return;
		}
		
		for (var j = 0; j <listLen; j++)
		{
			if (j != i)
			{
				if ((macAddress.toUpperCase() == macfilterlist[j].toUpperCase()))
				{
					AlertEx(macfilter_language['bbsp_themac'] + macAddress + macfilter_language['bbsp_macrepeat']);
					return false;
				}
			}
		}
	}
   
	if ('EDIT' == flag)
	{
		if (listLen >= SSIDnum)
		{
			AlertEx(wlanmacfil_language['bbsp_rulenum']);
			return;
		}
	}

    return true;
}

function AddMACList()
{
	if (false == setMacFilterPolicy())
	{
		return;
	}
	
	var macAddress = getElement('SourceMACAddress').value;
	if (false == CheckAddForm(macAddress))
	{
		setText('SourceMACAddress','');
		return;
	}
	var str = '';
	var action = ''; 
	var EnableMacFilter = enableFilter;
	
	 $.ajax({
     type : "POST",
     async : false,
     cache : false,
     data : "x.SourceMACAddress="+getValue('SourceMACAddress')+"&x.SSIDName="+CurSSIDName+"&x.Enable="+EnableMacFilter+"&x.X_HW_Token="+getValue('onttoken'),
     url : "add.cgi?x=InternetGatewayDevice.X_HW_Security.WLANMacFilter&RequestFile=html/not_find_file.asp",
     success : function(data) {
     },
     complete: function (XHR, TS) {
        XHR=null;
     }
    });
	setBtnDisable();
	window.location='/html/bbsp/wlanmacfilter/wlanmacfiltertde.asp'+'?SSID='+CurSSIDName; 
}

function EditMACList()
{
	if (-1 == selctIndex)
	{
		AlertEx(wlanmacfil_language['bbsp_chooserulealert']);
		return;
	}
	setDisable('maclist_'+selctIndex,0);
	setDisplay('trEdit',0);
	setDisplay('trDelAll',1);
	
}

function GetNewMacfilter()
{
	var NewMacfilterList = new Array();
	for (var i=0;i <= MacFilterNr - 1;i++)   
	{
		NewMacfilterList.push(getValue('maclist_'+i));
	}
	return NewMacfilterList;
}

function ApplyMACList()
{
	var NewMacfilterList = GetNewMacfilter();
	if (false == CheckEditForm(NewMacfilterList,'EDIT'))
	{
		updateMaclist();
		return;
	}
	
	var str = '';
	var action = '';
	var EnableMacFilter = enableFilter;
	var urlpara = "";
	var index = "";
	var Count = 0;
	var expList = new Array('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p');
	for (var i = 0; i <= MacFilterNr - 1; i++)
	{
		index = expList[i];
		Count++;
		if (Count > 1)
		{
			str +='&';
		}
		str += index+'.SourceMACAddress'+'='+NewMacfilterList[i];
		str += '&'+index+'.SSIDName'+'='+CurSSIDName;
		str += '&'+index+'.Enable'+'='+EnableMacFilter;
		if(i != 0){
		    urlpara += '&' ;
	    }
	    urlpara +=  index + '=' + MacFilter[i].domain;
	}
	str += '&x.X_HW_Token='+getValue('onttoken');
	action = 'set.cgi?' + urlpara;
	
	$.ajax({
     type : "POST",
     async : false,
     cache : false,
     data : str,
     url :  action + '&RequestFile=html/not_find_file.asp',
     success : function(data) {
     },
     complete: function (XHR, TS) {
        XHR=null;
     }
    });
    setBtnDisable();
	window.location='/html/bbsp/wlanmacfilter/wlanmacfiltertde.asp'+'?SSID='+CurSSIDName; 
}

function DelMACList(DelId)
{
	var idx = DelId.split('_')[1];
	var SelectCount = 0;
	var str = '';
	var action = '';
	if (0 == MacFilterNr)
	{
		AlertEx(wlanmacfil_language['bbsp_nonerulealert']);
		return;
	}
	var NewMacfilterList = GetNewMacfilter();
	if (false == CheckEditForm(NewMacfilterList,'DEL'))
	{
		updateMaclist();
		return;
	}
	
	if ('delmaclistall' == DelId)
	{
		for (var i=0;i <= MacFilterNr - 1;i++) 
		{
			SelectCount++;
			if (SelectCount > 1)
			{
				str +='&';
			}
			str += MacFilter[i].domain + '=' + '';
		}  
	}
	else
	{
		str += MacFilter[idx].domain + '=' + '';
	}
	str += '&x.X_HW_Token=' + getValue('onttoken');
	action = 'del.cgi?' +'x=InternetGatewayDevice.X_HW_Security.WLANMacFilter';
	
	if (enableFilter == 1 && Mode == 1)
	{
		if(ConfirmEx(wlanmacfil_language['bbsp_whitealert']))
		{
			 $.ajax({
				 type : "POST",
				 async : false,
				 cache : false,
				 data : str,
				 url : action + '&RequestFile=html/not_find_file.asp',
				 success : function(data) {
				 },
				 complete: function (XHR, TS) {
					XHR=null;
				 }
			});
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
			return;
		}
		 $.ajax({
			 type : "POST",
			 async : false,
			 cache : false,
			 data : str,
			 url : action + '&RequestFile=html/not_find_file.asp',
			 success : function(data) {
			 },
			 complete: function (XHR, TS) {
				XHR=null;
			 }
		});
	}
	setBtnDisable();
	window.location='/html/bbsp/wlanmacfilter/wlanmacfiltertde.asp'+'?SSID='+CurSSIDName; 
}

function updateMaclist()
{
	if (0 == Mode || 0 == MacFilterNr)
	{
		return;
	}
	for (var i=0;i <= MacFilterNr - 1;i++)   
	{
		setText('maclist_'+i, MacFilter[i].MACAddress);
	}
}

function showlistcontrol()
{
	if (0 == Mode || 0 == MacFilterNr)
	{
		return;
	}
	
	for (var i=0;i <= MacFilterNr - 1;i++)   
	{
		document.write('<tr id="record_' + i + '" align = "left" class="tabal_01">');
		document.write('<td class="tablecfg_title width_per40"></td>');
		document.write('<td class="tablecfg_right width_per60">');
		document.write('<input id="maclist_' + i + '" type="text" maxlength="17" value="'+ MacFilter[i].MACAddress +'" class="Selectmacaddr"/>');
		document.write('<img id="maclistimg_' + i + '" src="../../../images/cus_images/del.png" style="margin-left:5px;" onClick="DelMACList(this.id);"/>');
		document.write('</td>');
		document.write('</tr>');
	}
}
function showBtncontrol()
{
	if (0 == Mode || 0 == MacFilterNr)
	{
		return;
	}
	document.write('<tr id="trDelAll" align = "center" class="" style="display:block"><td>');
	document.write('<a id="applybtn" href="#" name="applybtn" class="helpclass" onClick="ApplyMACList();" style="text-decoration:none;">');
	document.write(wlanmacfil_language['bbsp_apply']);
	document.write('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;');
	document.write('</a>');
	document.write('<a id="delmaclistall" href="#" name="delmaclistall" class="helpclass" onClick="DelMACList(this.id);" style="text-decoration:none;">');
	document.write(wlanmacfil_language['bbsp_delall']);
	document.write('</a>');
	document.write('</td></tr>');
}

function ShowFilterEnable(enable)
{
	if(enable == 0)
	{
		$("#EnableMacFilter").attr("src", "../../../images/cus_images/btn_off.png");
	}
	else
	{
		$("#EnableMacFilter").attr("src", "../../../images/cus_images/btn_on.png");
	}
}

function GetFilterEnable()
{
	var FilterEnable = '';
	if (getElement('EnableMacFilter').getAttribute("src") == "../../../images/cus_images/btn_off.png")
	{
		FilterEnable = 0;
	}
	else
	{
		FilterEnable = 1;
	}
	return FilterEnable;
}

function getHeight(id)
{
	var item = id;
	var height;
	if (item != null)
	{
		if (item.style.display == 'none')
		{
			return 0;
		}
		if (navigator.appName.indexOf("Internet Explorer") == -1)
		{
			height = item.offsetHeight;
		}
		else
		{
			height = item.scrollHeight;
		}
		if (typeof height == 'number')
		{
			return height;
		}
		return null;
	}

	return null;
}

function adjustParentHeight()
{
	var dh = getHeight(document.getElementById("DivContent"));
	var height = dh > 0 ? dh : 0;
	window.parent.adjustParentHeight("MacfilterWarpContent", height+10);
}

function LoadFrame()
{
	ShowFilterEnable(enableFilter);
	adjustParentHeight();
}
</script>
</head>
<body onLoad="LoadFrame();" class="iframebody">
<div id="DivContent">
<div style="height:20px;"></div>
<div id="DivMacFilter" class="FuctionPageAreaCss">
	<div id="MacFilterTitle" class="FunctionPageTitleCss">
	<span id="MacFilterText" class="PageTitleTextCss" BindText="bbsp_macfilter_title"></span>
	</div>
	<div style="height:30px;"></div>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg"> 
		<tr> 
			<td class="PageSumaryTitleCss tablecfg_title width_per40" BindText='bbsp_inputmacaddr'></td> 
			<td class="tablecfg_right width_per60">
			<div>
				<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
				<input type='text' name="SourceMACAddress" id="SourceMACAddress" maxlength='17' class="Selectmacaddr"/> 
				<span class="gray" BindText="bbsp_maceg"></span> 
				<span>&nbsp;&nbsp;</span>
				<input type="button" id="btnAdd" class="BluebuttonGreenBgcss buttonwidth_100px" BindText="bbsp_add" onClick="AddMACList();"/>
			</div>
			</td> 
		</tr> 
	</table>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg"> 
		<tr>
			<td class="PageSumaryTitleCss tablecfg_title width_per70" BindText='bbsp_filtertilte' nowrap></td> 
			<td class="tablecfg_right width_per30">
			<div>
				<span BindText='bbsp_filterenable'></span> 
				<span>&nbsp;&nbsp;&nbsp;&nbsp;</span>
				<img src="../../../images/cus_images/btn_on.png" id="EnableMacFilter" onClick='SetFilterEnable();'/>
			</div>
			</td> 
		</tr>
	</table>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
		<script language="JavaScript" type="text/javascript">
			showlistcontrol();
		</script> 
	</table>
	<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
		<script language="JavaScript" type="text/javascript">
			showBtncontrol();
		</script> 
	</table>
	<div style="height:30px;"></div>
</div>
</div>
	<script>
		ParseBindTextByTagName(wlanmacfil_language, "span",  1);
		ParseBindTextByTagName(wlanmacfil_language, "td",    1);
		ParseBindTextByTagName(wlanmacfil_language, "input", 2);
	</script>

</body>
</html>
