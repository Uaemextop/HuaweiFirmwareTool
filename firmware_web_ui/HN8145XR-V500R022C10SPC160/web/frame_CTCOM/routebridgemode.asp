<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
<META http-equiv=Content-Type content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<title>中国电信—我的E家</title>
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
</head>

<script language="javascript">
var RouteStatus = <%HW_WEB_GetRouteStatus();%>;
var inter_index = -1;
function WANIP(domain,ipGetMode,serviceList,modeType,Tr069Flag)
{
	this.domain = domain;
	
	if (modeType.toString().toUpperCase().indexOf("BRIDGED") >= 0)
	{
		this.modeType = "BRIDGED";
	}
	else
	{
		this.modeType = "ROUTED";
	}
	
	this.ipGetMode = "DHCP";
	this.serviceList = serviceList;	
	this.Tr069Flag = Tr069Flag;
}

function WANPPP(domain,serviceList,modeType,Username,Password,IdleDisconnectTime,Tr069Flag,LastConnectionError)
{
	this.domain	= domain;
	
	if (modeType.toString().toUpperCase().indexOf("BRIDGED") >= 0)
	{
		this.modeType = "BRIDGED";
	}
	else
	{
		this.modeType = "ROUTED";
	}
   	
	this.ipGetMode = "PPPOE";
 	this.Username = Username;
  	this.Password = Password;

	this.Password = Password;
	 
  	this.IdleDisconnectTime = IdleDisconnectTime;    
  	this.serviceList = serviceList;
	this.Tr069Flag = Tr069Flag;
}
	
var WanIp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i},AddressingType|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG,WANIP);%>;
var WanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i},X_HW_SERVICELIST|ConnectionType|Username|Password|IdleDisconnectTime|X_HW_TR069FLAG,WANPPP);%>;

var Wan = new Array();

var g_CurrentDomain = '';

for (i=0, j=0; WanIp.length > 1 && j < WanIp.length - 1; i++,j++)
{
  if("1" == WanIp[j].Tr069Flag)
	{
		  i--;
    	continue;
	}
	Wan[i]	= WanIp[j];
}

for (j=0; WanPpp.length > 1 && j<WanPpp.length - 1; i++,j++)
{
	if("1" == WanPpp[j].Tr069Flag)
	{
		  i--;
    	continue;
	}
	Wan[i]	= WanPpp[j];
}
	
function isValidAscii(val)
{
    for ( var i = 0 ; i < val.length ; i++ )
    {
        var ch = val.charAt(i);
        if ( ch < ' ' || ch > '~' )
        {
            return ch;
        }
    }
    return '';
}

function isNum(str)
{
    var valid=/[0-9]/;
    var i;
    for(i=0; i<str.length; i++)
    {
        if(false == valid.test(str.charAt(i)))
        {
        return false;
        }
    }
    return true;
}


function CheckForm()
{
	var Username = document.getElementById('AccountValue').value;
	var Password = document.getElementById('PwdValue').value;
	var timearea = document.getElementById('TimeOut').value;

	if ((Username != '') && (isValidAscii(Username) != ''))        
	{  
		AlertEx("用户名含有非法字符！");          
		return false;       
	}
	
	if ((Password != '') && (isValidAscii(Password) != ''))         
	{  
		AlertEx("密码含有非法字符！");         
		return false;       
	}
	
	
	if((false == isNum(timearea)) || (timearea == ''))
	{
		AlertEx("无效的超时时间！");  
		return false;
	}

	var info = parseInt(timearea,10);
  if (info < 0 || info > 86400)
  {
      AlertEx("超时时间无效，请重新输入！");
      return false;
  }

	return true;
}

function ShowNoneWan()
{
	document.getElementById("InternetWorkType").innerHTML = "设备当前上网工作方式：--";	
	
	setText('AccountValue', "");
	setText('PwdValue', "");
	setText('TimeOut', "600");
	
	setDisable('AccountValue', 1);
	setDisable('TimeOut', 1);
	setDisable('PwdValue', 1);	
	setDisable('btnRouter', 1);
	setDisable('btnBridge', 1);
	
	return;
}

function filterChooseWan()
{
	var i = 0;
	
	for (i = 0; i < Wan.length; i++)
	{
		if ((Wan[i].serviceList.toString().toUpperCase().indexOf("INTERNET") < 0)
		 || (Wan[i].serviceList.toString().toUpperCase().indexOf("TR069") >= 0)
		 || (Wan[i].serviceList.toString().toUpperCase().indexOf("VOIP") >= 0)
         || (Wan[i].ipGetMode.toUpperCase() != "PPPOE"))
		{
			continue;
		}
		
		if ((Wan[i].modeType != "ROUTED") && (Wan[i].modeType != "BRIDGED"))
		{
			AlertEx("模式：" + Wan[i].modeType);
			continue;
		}
		
		g_CurrentDomain = Wan[i].domain;  
		inter_index = i;
		
		if (Wan[i].modeType == "ROUTED")
		{	
			document.getElementById("InternetWorkType").innerHTML = "设备当前上网工作方式：路由";
			setDisable('btnBridge', 0);
		}
		else
		{  	
			document.getElementById("InternetWorkType").innerHTML = "设备当前上网工作方式：桥接";				
			setDisable('btnBridge', 1);
		}
		
		setText('AccountValue', Wan[i].Username);
		setText('PwdValue', Wan[i].Password);
				
		if ((Wan[i].IdleDisconnectTime == '') || (Wan[i].IdleDisconnectTime == '180'))
		{
			setText('TimeOut', "600");
		}
		else
		{
			setText('TimeOut', Wan[i].IdleDisconnectTime);
		}
				
		setDisable('AccountValue', 0);
		setDisable('TimeOut', 0);
		setDisable('PwdValue', 0);	
		setDisable('btnRouter', 0);
			
		if (Wan[i].serviceList == "INTERNET")
		{
			break;
		}
	}
	
	return;
}

function LoadFrame()
{
	ShowNoneWan();
	
	if (0 == Wan.length)
	{
		return;
	}
	
	filterChooseWan();
	
	if (1 == RouteStatus)
	{
		setDisable('btnRouter', 1);
		setDisable('btnBridge', 1);
	}
	return;
}

function SubmitRouterParam()
{
	if (CheckForm() == true)
	{
		var Form = new webSubmitForm();
		Form.usingPrefix('y');
		Form.addParameter('Username',getValue('AccountValue'));
		Form.addParameter('Password',getValue('PwdValue'));
		Form.addParameter('IdleDisconnectTime',getValue('TimeOut'));
		Form.addParameter('ConnectionType',"IP_Routed");
		Form.addParameter('NATEnabled',1);
		Form.addParameter('ConnectionTrigger', "OnDemand");
		Form.addParameter('DNSEnabled', 1);
		Form.addParameter('DNSOverrideAllowed', 1);
		Form.endPrefix();
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));	
		var Url = 'set.cgi?'
				+ 'y=' + Wan[inter_index].domain
				+ '&RequestFile=routebridgesucc.asp'
				+ '&RequestErrorFile=routebridgefailed.asp';
		Form.setAction(Url);
		Form.submit();
	}
}


function SubmitBridgeParam()
{

	if (CheckForm() == true)
	{
		var Form = new webSubmitForm();
		Form.usingPrefix('y');
		Form.addParameter('Username',getValue('AccountValue'));
		Form.addParameter('Password',getValue('PwdValue'));
		Form.addParameter('IdleDisconnectTime',getValue('TimeOut'));
		Form.addParameter('ConnectionType',"PPPoE_Bridged");
		Form.endPrefix();
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));	
		var Url = 'set.cgi?'
				+ 'y=' + Wan[inter_index].domain
				+ '&RequestFile=routebridgesucc2.asp'
				+ '&RequestErrorFile=routebridgefailed.asp';
		Form.setAction(Url);
		Form.submit();
	}
}

function SubmitLogout()
{
	var Form = new webSubmitForm();
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('/logout.cgi?RequestFile=/html/logout.html');
	Form.submit();
}

function GetXmlHttp()
{
	var xmlHttp;
	if(window.ActiveXObject) 
	{
		try 
		{ 
			xmlHttp = new ActiveXObject("Msxml2.XMLHTTP");
		}
		catch (e) 
		{		
		}
		
		if (xmlHttp == null)
		try
		{ 
			xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
		} 
		catch (e) 
		{ 
		}
    }
    else 
    {
        xmlHttp = new XMLHttpRequest();
    }
    
    return xmlHttp;
}

function CheckResponseData(DataInfo)
{		
		try 
		{	
		    var EvalData = hexDecode(DataInfo);
		    return EvalData;
		} catch (e)
		{
			  	clearInterval(Outtime);
				
					window.location.replace("/login.asp");
					return true;
		}
}
function SendTimeoutRequest()
{
	try 
	{	
		var xmlHttp = GetXmlHttp();
		xmlHttp.onreadystatechange=function()
		{
			if (xmlHttp.readyState==4&&xmlHttp.status==200)
			{
				var result = CheckResponseData(xmlHttp.responseText);
				if(1 == result)
				{
					clearInterval(Outtime);
					
					window.location.replace("/login.asp");
				}
			}
		};
		
		xmlHttp.open("get", "asp/getTime.asp", true);
		xmlHttp.send(null);
	} catch (e)
	{
	}
}

var Outtime = setInterval("SendTimeoutRequest()", 1000);

</script>
<body onload="LoadFrame();"> 
<form> 
<div align="center"> 
<TABLE cellSpacing="0" cellPadding="0" width="808" align="center" border="0"> 
<TBODY> 
<TR> 
<TD ><IMG height="137" src="images/register_banner.jpg" width="808"></TD> 
</TR> 
<TR> 
<TD> <TABLE cellSpacing="0" cellPadding="0" align="middle" width="808" border="0"> 
<TBODY> 
<TR> 
<TD width="77" background="images/bg.gif" rowSpan="3"></TD> 
<TD align="center" width="653" height="323" background="images/register_gdinfo_scct.jpg">

<TABLE cellSpacing="0" cellPadding="0" width="96%" height="16%" border="0">
<TR> 
<TD width="15%"></TD>
<TD align="center" width="08%"></TD>
<TD valign="middle" width="62%"><font style="font-size: 16px;">	
</TD>
<TD align="right" width="20%"><A href="#" onClick="SubmitLogout();"><font style="font-size: 14px;" color="#000000">返回登录页面</FONT></A></TD>
</TR> 
</TABLE> 
<TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%" style="font-size: 14px;">					                         
<TR><TD align="center" colSpan="2" height="10"><font style="font-size: 16px;"><span id="InternetWorkType"></span>
	</font></TD></TR>
<TR>
 <TD align="center" colSpan="2" height="25">请输入宽带上网账号和上网密码</TD>
</TR>
<TR>
<TD  valign="bottom" align="right" width="30%" height="25">上网账号：</TD>
<TD valign="bottom" align="left" width="70%">
<input name="AccountValue" id="AccountValue" type="text" style="width:150px;" maxlength="63">
<font style="font-size: 14px;">（0-63）个字符</font>
</TD>
</TR>
<TR>
<TD valign="bottom" align="right" width="30%" height="25">上网密码：</TD>
<TD valign="bottom" align="left" width="70%">
	<input type="password" autocomplete="off" name="PwdValue" id="PwdValue" style="width:150px;" maxlength="63">
<font style="font-size: 14px;">（0-63）个字符</font>
</TD>
</TR>
<TR>
<TD  valign="bottom" align="right" width="30%" height="25">路由超时时间：</TD>
<TD valign="bottom" align="left" width="70%">
	<input type="text" name="TimeOut" id="TimeOut" style="width:150px;" maxlength="5">
	<font style="font-size: 14px;">（0-86400）秒</font>
</TD>
</TR>
<TR>
  <TD  class="table_submit pad_left5p" align="center" colSpan="2" height="35">
  <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
  <input name="btnRouter" class="submit" id="btnRouter" onClick="SubmitRouterParam();" type="button" value="转成路由"> 
  <input name="btnBridge" id="btnBridge" type="button" class="submit"  onClick="SubmitBridgeParam();" value="桥接复原">
  </TD>
</TR> 
<TR> 
<TD align="center" colSpan="2" width="100%" height="10"><font style="font-size: 14px;">中国电信客服热线10000号</font></TD>
</TR> 
<TR> 
<TD align="left" colSpan="2" height="60"></TD> 
</TR> 
</TABLE> 
<TD width="78" background="images/bg.gif" rowSpan="3"></TD> 
</TR> 
</TBODY> 
</TABLE> 
</TD> 
</TR> 
</TBODY> 
</TABLE> 
</div> 
</form> 
</body>
</html>
