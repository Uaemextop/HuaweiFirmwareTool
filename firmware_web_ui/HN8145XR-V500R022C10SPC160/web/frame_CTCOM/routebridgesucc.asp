<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
 	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
 <title> 提示 </title>
  <style type="text/css">
  </style>
 </head>
 <script languaBasicInfoge="javascript">
 
function BasicInfo(_Domain, _LimitMode, _TotalLimit)
{
    this.Domain = _Domain;
    this.LimitMode = _LimitMode;
    this.TotalLimit = _TotalLimit;
}

function TypeLimitInfo(_Domain, _Enable, _DeviceType, _LimitNum)
{
    this.Domain = _Domain;
    this.Enable = _Enable;
    this.DeviceType = _DeviceType;
    this.LimitNum = _LimitNum;
}

function UpdateUI(BasicInfo, TypeLimitInfoList)
{
    var HtmlCode = "";
    
    if (null == BasicInfo)
        HtmlCode = "已完成路由方式设置。";
    
    if ("GlobalLimit" == BasicInfo.LimitMode)
    {
    	if ("0" == BasicInfo.TotalLimit)
    	{
    	    HtmlCode = "已完成路由方式设置。";
    	}
    	else
    	{
    	    HtmlCode = "已完成路由方式设置，可支持" + BasicInfo.TotalLimit + "个终端同时上网。";
    	}
    }
    else if ("TypeLimit" == BasicInfo.LimitMode)
    {
    	var typelimit = 0;
    	var i = 0;
        var RecordCount = TypeLimitInfoList.length - 1;
        
    	for (i = 0; i < RecordCount; i++)
        {
    	    if ("1" == TypeLimitInfoList[i].Enable)
    	    	typelimit += parseInt(TypeLimitInfoList[i].LimitNum);
        }
        if (0 == typelimit)
        {
            HtmlCode = "已完成路由方式设置。";
        }
        else
        {
            HtmlCode = "已完成路由方式设置，可支持" + typelimit + "个终端同时上网。";
        }
    }
    else
    {
        HtmlCode = "已完成路由方式设置。";
    }

    return HtmlCode;
}

var BasicInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.X_HW_AccessLimit,Mode|TotalTerminalNumber,BasicInfo);%>;
var TypeLimitInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.X_HW_AccessLimit.TypeLimit.{i},Enable|VenderClassId|LimitNumber,TypeLimitInfo);%>;
var BasicInfo = BasicInfoList[0];

function Submit() 
{
    window.location="routebridgemode.asp";
}

 </script>
<body>
<br>
<table class="tabal_bg" cellpadding="0" cellspacing="1" width="100%">
<tr align="center">
<script language="JavaScript" type="text/javascript">
document.write(UpdateUI(BasicInfo, TypeLimitInfoList));
document.write("若不能上网，请核实“上网账号”和“上网密码”是否正确录入，若需再次录入请点击“转成路由”按键。若需恢复宽带连接方式，请先点击“桥接复原”按键，谢谢！");
</script>	
</tr>
   <tr>
	  <td class="width_25p"></td>
		<td class="table_submit" align="center">
			<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
			<button id="btnApply_ex" name="btnApply_ex" type="button" class="submit" onClick="Submit();"><script>document.write("返回");</script></button>
	</td>
	  
	</tr>
</table>

</body>
</html>