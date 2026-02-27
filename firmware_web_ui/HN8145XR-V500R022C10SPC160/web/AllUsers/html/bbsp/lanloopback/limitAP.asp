<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>Limit AP</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" type="text/javascript">
var enableRingChkDownloadLan = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_FeatureList.BBSPCustomization.RingChkDownLan);%>';

function LoadFrame()
{
    var enable = (enableRingChkDownloadLan == '0') ? false:true;
    setCheck('enableRingChkDownloadLan_checkbox', enable);
}

function CheckForm(type)
{
    setDisable('Btn_Submit_button', 1);
    setDisable('Btn_Cancel_button', 1);
    return true;
}

function CancelConfig()
{
    LoadFrame();
}

function AddSubmitParam(Form, type)
{
   Form.addParameter('x.RingChkDownLan',getCheckVal('enableRingChkDownloadLan_checkbox'));
   Form.addParameter('x.X_HW_Token', getValue('onttoken'));
   Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_FeatureList.BBSPCustomization'
   	              + '&RequestFile=html/bbsp/lanloopback/limitAP.asp');
   Form.submit();
}


function RingChkDownloadLanSubmit()
{
    if (getCheckVal('enableRingChkDownloadLan_checkbox')) {
        if (ConfirmEx("启用后AP在环回之后会优先关闭lan口")) {
            Submit();
        }
        return;
    }
    Submit();
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<form id="ConfigForm" action=""> 
  <table width="100%"  border="0" cellpadding="0" cellspacing="0" id="tabal_bg"> 
    <tr> 
      <td class="prompt"> <table width="100%" border="0" cellspacing="0" cellpadding="0"> 
          <tr> 
            <td class="title_common"><label id="RingChkDownloadLan_lable">启用后AP在环回之后会优先关闭lan口</label></td> 
          </tr> 
        </table></td> 
    </tr> 
  </table>
  <div class="title_spread"></div>
  <table width="100%"   cellpadding="0" cellspacing="1"> 
    <tr > 
      <td class="table_title width_30p"><label id="enableRingChkDownloadLan">下挂AP出现环回后优先关闭lan口:</label></td> 
      <td class="table_right"><input id="enableRingChkDownloadLan_checkbox" name="enableRingChkDownloadLan_checkbox" type="checkbox" value="false"></td> 
    </tr> 
  </table> 
   <div class="button_spread"></div>
  <table width="100%"  cellpadding="0" cellspacing="0" class="table_button"> 
    <tr align="right">
      <td class="width_per25"></td> 
      <td> 
	    <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
	  	<button id="Btn_Submit_button" name="Btn_Submit_button" type="button" class="submit" onClick="RingChkDownloadLanSubmit();">确定</button>
        <button id="Btn_Cancel_button" name="Btn_Cancel_button"  type="button" class="submit" onClick="CancelConfig();">取消</button>
	 </td> 
    </tr> 
  </table> 
</form> 
</body>
</html>
