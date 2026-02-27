<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" type="text/javascript">
var sysUserType = '0';
var curUserType = '<%HW_WEB_GetUserType();%>';
var curWebFrame = '<%HW_WEB_GetWEBFramePath();%>';
var IsSupportIot = '<%HW_WEB_GetIotStatus();%>';

function setAllDisable()
{
	setDisable('btnRestoreDftCfg',1);
}
 
 
function GetLanguageDesc(Name)
{
    return RestoreLgeDes[Name];
}

function LoadFrame()
{ 

}

function RestoreDefaultCfg()
{
	if(1 == parseInt(IsSupportIot))
	{
		RestoreDefaultChoose();
	}
	else
	{
		if(ConfirmEx(GetLanguageDesc("s0a01")))
		{
			var Form = new webSubmitForm();
			setDisable('btnRestoreDftCfg', 1);
			Form.setAction('restoredefaultcfg.cgi?' + 'RequestFile=html/ssmp/ssmp/reset.asp');
			Form.addParameter('x.X_HW_Token', getValue('onttoken'));
			Form.submit();
		}
	}
}

function RestoreDefaultChoose()
{
	setDisable('btnRestoreDftCfg',1);
	$('#PageBaseMask').css("display", "block");	
	$('#MBIOTRestoreInfo').css("display", "block");
}

function ApplyRestore()
{
	$('#PageBaseMask').css("display", "none");	
	$('#MBIOTRestoreInfo').css("display", "none");
	var Form = new webSubmitForm();
	setDisable('btnRestoreDftCfg', 1);
	
	if(getCheckVal('EnableCheckBox') == 1)
	{
		Form.addParameter('ParaKey', "ResetIot");
	}
	
	Form.setAction('restoreIotdefcfg.cgi?&RequestFile=html/ssmp/ssmp/reset.asp');
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.submit();
}

function CancelRestore()
{
	$('#PageBaseMask').css("display", "none");	
	$('#MBIOTRestoreInfo').css("display", "none");
	setDisable('btnRestoreDftCfg',0);
}

</script>
</head>
<body class="mainbody" onLoad="LoadFrame();"> 
<div id="MBIOTRestoreInfo" class="MBIOTRestoreInfo">
<div class="title_spread"></div>
<div class="title_spread"></div>
<div class="title_spread"></div>
<div id="iotAlarmInfo" class="iotResetHeadSpanCss"><span id="AlarmInfoSpan" BindText="s0a04"></span></div>
<div class="title_spread"></div>
<div class="title_spread"></div>
<div class="title_spread"></div>
<div id="CheckBoxArea" class="iotResetHeadSpanCss">
<input id="EnableCheckBox" name="EnableCheckBox" class="CheckBoxMiddle" value='1' type='checkbox'><span id="CheckInfoSpan" BindText="s0a05"></span>
</div>
<div class="title_spread"></div>
<div class="title_spread"></div>
<div class="title_spread"></div>
<div id="IotRestroeButtonCss" class="IotRestroeButtonCss">
<input type="button"  class="ApplyButtoncss buttonfloatleft buttonwidth_100px" id="ApplyRestore" onClick="ApplyRestore(this);" value="" BindText="s0a06"/>
<input type="button"  class="ApplyButtoncss buttonfloatright buttonwidth_100px" id="CancelRestore" onClick="CancelRestore();" value="" BindText="s0a07"/>
</div><!-- end of ChooseButton-->
</div>

<div>
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("restore", GetDescFormArrayById(RestoreLgeDes, "s0a03"), GetDescFormArrayById(RestoreLgeDes, "s0a02"), false);
</script> 
<div class="title_spread"></div>
  <table width="100%" cellpadding="0" cellspacing="0"> 
    <tr> 
      <td> 
      	<input  class = "ApplyButtoncss buttonwidth_150px_250px" name="btnRestoreDftCfg" id="btnRestoreDftCfg" type='button' onClick='RestoreDefaultCfg()'  BindText="s0a03" > 
		<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
      </td> 
    </tr> 
  </table> 
</div> 
<script>
ParseBindTextByTagName(RestoreLgeDes, "td",     1);
ParseBindTextByTagName(RestoreLgeDes, "input",  2);
ParseBindTextByTagName(RestoreLgeDes, "div",  1);
ParseBindTextByTagName(RestoreLgeDes, "span", 1);
</script>

</body>
</html>
