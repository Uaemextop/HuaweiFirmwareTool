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
 <script language="javascript">
function Submit() {
    window.location="routebridgemode.asp";
}
 </script>
<body>
<br>
<p align="center">
<script language="JavaScript" type="text/javascript">
document.write("已完成宽带连接方式设置，请开启电脑桌面上的“宽带连接”软件拨号上网，谢谢！");
</script>	
</p>
<table class="tabal_bg" id="arpInst" cellpadding="0" cellspacing="1" width="100%">
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