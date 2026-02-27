<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
    <meta http-equiv="Pragma" content="no-cache" />
    <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
    <title></title>
    <style type="text/css">
    </style>
</head>
<body onload="loadframe();">
<p id="tips" align="center" style="position:absolute;font-size:25px;display:none">
<script language="JavaScript" type="text/javascript">

var clientIP = '<%WEB_GetFttrClientIP();%>';
if (clientIP == "") {
    clientIP = "----";
}

function ChangeStyle() {
    $(window).resize(function(){
        $('#tips').css({
            left:($(window).width()-$('#tips').outerWidth())/2,
            top:($(window).height()-$('#tips').outerHeight())/2
        });
    });
}

document.write("本路由器设备限制在中国移动宽带网络下使用，请切换网络重试。<br>设备当前网络IP地址为" + clientIP + "。");

function loadframe() {
    $('#tips').css({
        left:($(window).width()-$('#tips').outerWidth())/2,
        top:($(window).height()-$('#tips').outerHeight())/2
    });

    ChangeStyle();
    document.getElementById('tips').style.display = "";
}

</script>
</p>
</body>
</html>
