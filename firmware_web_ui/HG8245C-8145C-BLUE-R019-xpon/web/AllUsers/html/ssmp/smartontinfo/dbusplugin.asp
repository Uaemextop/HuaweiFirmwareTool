<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Pragma" content="no-cache">
<title>Bundle Information</title>
<script>
var token = '<%HW_WEB_GetToken();%>';

function AccRefreshSubmit( )
{
   window.location="dbusplugin.asp";
}

function getPath(obj) 
{
	if (obj)
	{
		if (window.navigator.userAgent.indexOf("MSIE") >= 1)
		{
		    obj.select(); 
		    return document.selection.createRange().text;
	    	}
		else if (window.navigator.userAgent.indexOf("Firefox") >= 1) 
		{
			if (obj.files) 
			{
		    		return obj.files.item(0).getAsDataURL();
			}
			
			return obj.value;
		}
		
	    	return obj.value;
	}
}

function startFmkOp()
{
	document.getElementById("Fmk_start").style.display = "none";
	document.getElementById("Fmk_stop").style.display = "block";
	var Form = new webSubmitForm();
	Form.addParameter('x.X_HW_Token', token);
	Form.setAction('SetFmkOpType.cgi?optype=start&RequestFile=html/ssmp/smartontinfo/dbusplugin.asp');
	//DisableAllButton();
	Form.submit();
}

function stopFmkOp()
{
	document.getElementById("Fmk_start").style.display = "block";
	document.getElementById("Fmk_stop").style.display = "none";
	var Form = new webSubmitForm();
	Form.addParameter('x.X_HW_Token', token);
	Form.setAction('SetFmkOpType.cgi?optype=stop&RequestFile=html/ssmp/smartontinfo/dbusplugin.asp');
	//DisableAllButton();
	Form.submit();
}

function recoverFmkOp()
{
	var Form = new webSubmitForm();
	Form.addParameter('x.X_HW_Token', token);
	Form.setAction('SetFmkOpType.cgi?optype=recover&RequestFile=html/ssmp/smartontinfo/dbusplugin.asp');
	//DisableAllButton();
	Form.submit();
}

function upgradeFmkOp()
{
	var uploadForm = document.getElementById("fr_upgradeImage");
	if ((window.navigator.userAgent.indexOf("MSIE 6.0") >= 1)
	 || (window.navigator.userAgent.indexOf("MSIE 7.0") >= 1)
	 || (window.navigator.userAgent.indexOf("MSIE 8.0") >= 1))
	{
		var filePath = getPath(document.getElementById("t_file2"));
	}
	else
	{
		var tfile = document.getElementById("t_file2");
		var filePath = tfile.value;
	}
	uploadForm.action = "SetFmkOpType.cgi?optype=upgrade&RequestFile=html/ssmp/smartontinfo/dbusplugin.asp&file=" + filePath;
	//DisableAllButton();
	uploadForm.submit();
}
function fchange()
{
	upgradeFmkOp() ;
}

function StartFileOpt()
{
 	XmlHttpSendAspFlieWithoutResponse("../common/StartFileLoad.asp");
}

function SetNullString(str)
{
 	if (str == "")
	{
	    return "--"
	}
	else
	{
	    return str;
	}
}

function GetPlatSatus(linkValue, platName)
{
 	var linkStatus;
	if(linkValue <= 1)
	{
		linkStatus = "未连接";	
	}
	else if(linkValue == 2)
	{
		linkStatus = "正在尝试连接";
	}
	else if(linkValue == 3)
	{
		linkStatus = "向" + platName + "注册中";
	}
	else if(linkValue == 4)
	{
		linkStatus = "向" + platName + "心跳保活中";
	}
	else if(linkValue == 5)
	{
		linkStatus = "与" + platName + "等待下一次心跳中";
	}
	else if(linkValue == 6)
	{
		linkStatus = "尝试连接" + platName + "失败";
	}
	else
	{
		linkStatus = "未连接";
	}
	
	return linkStatus;
}
</script>
</head>

<body class="mainbody">
<!--平台连接情况-->
<div>
<div class="func_title"><label>平台连接情况：</label></div>
  <table class="tabal_bg width_100p" cellspacing="1" id="bundleid"> 
  <tr align="left"> 
    <td width="10%" class="table_title" rowspan="2">分发平台</td>
    <td width="25%" class="table_title">平台地址</td> 
    <td width="25%" class="table_title">连接状态</td> 
    <td width="40%" class="table_title">错误描述</td>  
  </tr> 
  <tr align="left"> 
    <script language="JavaScript" type="text/javascript">
		function stPlatInfo(drb_address, drb_status, drb_msg, opt_address, opt_status, opt_msg, plug_address, plug_status, plug_msg)
		{
			this.drb_address = drb_address;//分发平台地址
			this.drb_status = drb_status;//分发平台连接状态
			this.drb_msg = drb_msg;//分发平台错误描述
			this.opt_address= opt_address;//运营平台地址
			this.opt_status = opt_status;//运营平台连接状态
			this.opt_msg = opt_msg;//运营平台错误描述
			this.plug_address = plug_address;//插件中心地址
			this.plug_status = plug_status;//插件中心连接状态
			this.plug_msg = plug_msg;//插件中心错误描述
		}
		var plat = <%HW_WEB_GetDbusPlatformInfo(stPlatInfo);%>;
		var DbusPlat = plat[0];
	
		var linkStatus;
		if(DbusPlat.drb_status <= 1)
		{
			linkStatus = "未连接";	
		}
		else if(DbusPlat.drb_status == 2)
		{
			linkStatus = "正在尝试连接分发平台";
		}
		else if(DbusPlat.drb_status == 3)
		{
			linkStatus = "与分发平台保持连接中";
		}
		else if(DbusPlat.drb_status == 4)
		{
			linkStatus = "与分发平台连接结束";
		}
		else if(DbusPlat.drb_status == 5)
		{
			linkStatus = "尝试连接分发平台失败";
		}
		else
		{
			linkStatus = "未连接";
		}
		
		DbusPlat.drb_msg = SetNullString(DbusPlat.drb_msg);
		DbusPlat.drb_address = SetNullString(DbusPlat.drb_address);

		document.write('<TD width="25%" class="table_right">' + htmlencode(DbusPlat.drb_address) + '</TD>');
		document.write('<TD width="25%" class="table_right">' + htmlencode(linkStatus) + '</TD>');
		document.write('<TD width="35%" class="table_right">' + htmlencode(DbusPlat.drb_msg) + '</TD>');
	</script>
  </tr>  
  <tr align="left"> 
    <td width="10%" class="table_title" rowspan="2">运营平台</td>
    <td width="25%" class="table_title">平台地址</td> 
    <td width="25%" class="table_title">连接状态</td> 
    <td width="40%" class="table_title">错误描述</td>  
  </tr> 
  <tr align="left"> 
	<script language="JavaScript" type="text/javascript">
	    var OptStatus = GetPlatSatus(DbusPlat.opt_status, "运营平台");
		DbusPlat.opt_address = SetNullString(DbusPlat.opt_address);
		DbusPlat.opt_msg     = SetNullString(DbusPlat.opt_msg);
		document.write('<TD width="25%" class="table_right">' + htmlencode(DbusPlat.opt_address) + '</TD>');
		document.write('<TD width="25%" class="table_right">' + htmlencode(OptStatus) + '</TD>');
		document.write('<TD width="35%" class="table_right">' + htmlencode(DbusPlat.opt_msg) + '</TD>');
	</script>
  </tr> 
  <tr align="left"> 
    <td width="10%" class="table_title" rowspan="2">插件中心</td>
    <td width="25%" class="table_title">平台地址</td> 
    <td width="25%" class="table_title">连接状态</td> 
    <td width="10%" class="table_title">错误描述</td>  
  </tr> 
  <tr align="left"> 
	<script language="JavaScript" type="text/javascript">
	    var PlugStatus = GetPlatSatus(DbusPlat.plug_status, "插件中心");
		DbusPlat.plug_address = SetNullString(DbusPlat.plug_address);
		DbusPlat.plug_msg     = SetNullString(DbusPlat.plug_msg);
		document.write('<TD width="25%" class="table_right">' + htmlencode(DbusPlat.plug_address) + '</TD>');
		document.write('<TD width="25%" class="table_right">' + htmlencode(PlugStatus) + '</TD>');
		document.write('<TD width="35%" class="table_right">' + htmlencode(DbusPlat.plug_msg) + '</TD>');
	</script>
  </tr> 
</table> 
</div>
</br></br>
<!--系統分区信息-->
<div>
  <div class="func_title"><label id = "Title_base_lable">系統分区信息：</label></div>
  <div style="width:100%;overflow-x:auto;">
    <table class="tabal_bg width_100p" cellspacing="1" id="bundleid">  
      <tr align="left"> 
		<td width="" class="table_title" nowrap>SAF版本</td> 
		<td class="table_title" nowrap>中间件版本</td> 
		<td class="table_title" nowrap>云客户端版本</td> 
		<td class="table_title" nowrap>备份区</td>
		<td class="table_title" nowrap>活动区</td> 
		<td class="table_title" nowrap>暂停/开始</td> 
		<td class="table_title" nowrap>恢复</td> 
		<td class="table_title" nowrap>升级</td>
	  </tr> 
	  <tr align="left"> 
		<script type="text/javascript" language="javascript">
			function stFmkInfo(middleVersion, safVersion, cloudVersion,activeNumber, backupNumber)
			{
				this.middleVersion = middleVersion;//中间件版本号
				this.safVersion = safVersion;//SAF版本号
				this.cloudVersion = cloudVersion;//云客户端版本号
				this.activeNumber = activeNumber;//活动分区号
				this.backupNumber = backupNumber;//备份分区号
			}
			var temp = <%HW_WEB_GetDbusFmkworkInfo(stFmkInfo);%>;
			var Fmkwork = temp[0];
			//var Fmkwork = new stFmkInfo("fmk1.0","daf1.0","cct1.0","18","17");
			
			document.write('<TD class="table_right" nowrap>' + htmlencode(Fmkwork.safVersion) + '</TD>');
			document.write('<TD class="table_right" nowrap>' + htmlencode(Fmkwork.middleVersion) + '</TD>');
			document.write('<TD class="table_right" nowrap>' + htmlencode(Fmkwork.cloudVersion) + '</TD>');
			document.write('<TD class="table_right" nowrap>' + htmlencode(Fmkwork.backupNumber) + '</TD>');
			document.write('<TD class="table_right" nowrap>' + htmlencode(Fmkwork.activeNumber) + '</TD>');
			document.write('<TD class="table_right">');
			document.write('<input id="Fmk_stop" name="Fmk_stop" type="button" value="暂停" onClick="stopFmkOp();"/>');
			document.write('<input id="Fmk_start" name="Fmk_start" type="button" value="开始" onClick="startFmkOp();"/>');
			document.write('</TD>');
			document.write('<TD class="table_right"><input type="button" value="恢复" onClick="recoverFmkOp();"/></TD>');
			document.write('<TD class="table_right">');
			document.write('<form method="post" enctype="multipart/form-data" name="fr_upgradeImage" id="fr_upgradeImage">');
			document.write('<input type="hidden" id="hwonttoken" name="onttoken" value="<%HW_WEB_GetToken();%>" />');
			document.write('<input type="file" name="browse" style="width:40px;" id="t_file2" title="选择文件" size="12" onblur="StartFileOpt();" onchange="fchange();" />');
			document.write('<input name="update" type="button" title="升级"  value="升级" onClick="upgradeFmkOp();" />');
			document.write('</form>');
			document.write('</TD>');
			
			var status = '<%HW_WEB_GetFmkStatus();%>';
			if(status == 'start'){
				document.getElementById("Fmk_start").style.display = "none";//隐藏开始按键
				document.getElementById("Fmk_stop").style.display = "block";//显示暂停按键
			}else{
				document.getElementById("Fmk_start").style.display = "block";//显示开始按键
				document.getElementById("Fmk_stop").style.display = "none";//隐藏暂停按键
			}
		</script> 
	  </tr> 
    </table> 
	</br>
  </div>
</div>
</br>
<!--日志-->
<div>
  <div class="title_with_desc">插件配置下发记录：</div>
  <table width="70%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg" id="SysLogInst">
    <tr class="head_title">
      <td class="width_30p" id="log_1_1_table"><div class="align_center">日期/时间</div></td>
      <td class="width_70p" id="log_1_2_table"><div class="align_center">消息</div></td>
    </tr>
	<script language="JavaScript" type="text/javascript">
	var DbusPluginLog = '<%HW_WEB_GetDbusPluginLog();%>';
	if(DbusPluginLog!=null){
		var ResultLog = DbusPluginLog.split("\n");
		var IDtable = 1;
		for (var i = 0; i < ResultLog.length -1; i++ )
		{
			var loginof =ResultLog[i];
			var logtime = loginof.substring(0,19);
			var logalert = loginof.substring(19,loginof.length);		
			var id_time = "log_2_" + (IDtable++) + "_table";
			var id_alert= "log_2_" + (IDtable++) + "_table";
			
			document.write('<tr class="tabal_center01 ">');	
			document.write('<TD id="' + id_time +'">' + htmlencode(logtime) + '</TD>');
			document.write('<TD id="' + id_alert + '" title="'+htmlencode(logalert)+'">'+GetStringContent(htmlencode(logalert), 64)+'</TD>');  					
			document.write('</tr>');	
		}
	}else{
		document.write('<tr class="tabal_center01 ">');	
		document.write('<TD>' + '-' + '</TD>');
		document.write('<TD>' + '-' + '</TD>');  					
		document.write('</tr>');
	}
	</script>
  </table> 
  <input class="submit" name="AccRefresh_button" id="AccRefresh_button" type="button" value="刷新" onClick="AccRefreshSubmit();">  
</div>
</body>
</html>
