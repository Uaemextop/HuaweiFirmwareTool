<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title></title>
<script type="text/javascript">
var ctrgflag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';

function requestCgi()
{
	$.ajax({
            type : "GET",
            async : true,
            cache : false,
            url : "asp/GetProvCode.asp",
            success : function(data) {
                if (data != '') {
                    clearInterval(TimerHandle);
                    window.CfgFtWordArea = data;
                    self.parent.location = "/acsChoosearea.asp";
                }
            }
        });
}
if (ctrgflag == '1') {
    var TimerHandle = setInterval("requestCgi()", 5000);
}
</script>
</head>
<body onload=""> </body>
</html>
