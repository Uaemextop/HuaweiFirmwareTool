<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" type="text/javascript">
var nceEnable = '<%WLAN_GetNceRemoteStatus();%>';

function LoadFrame() {
    setDisplay("nceEnableDiv", 1);
    setDisplay("nceEnableDivSpread", 1);
    setCheck("EnableNce", nceEnable);
}

function SubmitNceEnable() {
    var enable = getCheckVal("EnableNce");
    if (enable == 1) {
        if (ConfirmEx("远程运维会获取用户拨号、域名请求、ARP协议报文，对于数据报文会读取报文头部，不会读取内容，请确认是否同意?") == false) {
            setCheck("EnableNce", 0);
            return;
        }
    }
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        data :"stats="+enable,
        url : "./GetNceStatus.asp",
        success : function(data) {
            window.location.reload();
        }
    });
}
</script>
</head>

<body  class="mainbody pageBg" onLoad="LoadFrame();"> 
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("debuglogview", "NCE远程运维", "在本页面上，您可以进行使能NCE远程运维的操作", false);
</script> 
<div class="title_spread"></div>
<div id="nceEnableDiv" style="display:none;">
    <table width="100%" cellpadding="0" cellspacing="0" class="tabal_noborder_bg">
        <tbody>
            <tr border="1">
                <td class="table_title width_per25">
                    <script>document.write("使能NCE远程运维")</script>
                </td>
                <td class="table_right width_per75">
                    <input id="EnableNce" type="checkbox" realtype="CheckBox" class="CheckBox" onclick="SubmitNceEnable(this);">
                </td>
            </tr>
        </tbody>
    </table>
</div>
<div id="nceEnableDivSpread" class="func_spread"></div>
</body>
</html>
