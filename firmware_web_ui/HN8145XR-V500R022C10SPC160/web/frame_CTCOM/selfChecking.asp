<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<title>设备自检中</title>

<style type="text/css">

body{ 
text-align:center; 
margin-top:100px;
} 
.divCenter
{
	text-align:center; 
}
.selfCheckTip{
	font-family: "Arial", "";
	font-size: 14px;
}
.graph{ 
width:450px; 
border:1px solid orange; 
height:25px; 
} 
#bar{ 
display:block; 
background:orange; 
float:left; 
height:100%; 
text-align:center; 
} 
</style>

<script language="JavaScript" type="text/javascript">

var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
var g_requestCgiCount = 0;
var g_barWidth;
var TimerHandle = null;
var detectionsState=""

function setProgress()
{
	g_barWidth = g_requestCgiCount *5;
	varbar = document.getElementById("bar");
	varbar.style.width = g_barWidth + "%"; 
	varbar.innerHTML = varbar.style.width; 
}

function displayTipInfo()
{
	g_requestCgiCount = g_requestCgiCount + 1;
	

	
	if (g_requestCgiCount >= 18 && g_requestCgiCount < 20)
	{
	    g_requestCgiCount = 18;   
	}
	
	setProgress();
	if (g_requestCgiCount >= 20)
	{
		clearInterval(TimerHandle);
		clearInterval(TimerHandle1);
		window.location="/selfCheck_result.asp";
	}
	else if ( (g_requestCgiCount >= 1) && ("Complete" == detectionsState))
	{
		g_requestCgiCount = 19;	
	}
		
}
function requestCgi()
{
	$.ajax({
			type : "POST",
			async : true,
			cache : false,
			url : "asp/GetDetectionsResult.asp",
			success : function(data) {
				
				detectionsState=data;
				
			}
		});
		
	displayTipInfo();
}
document.onkeydown = function(e)
{
	var theEvent = window.event || e;     
	var code = theEvent.keyCode || theEvent.which;    
	if (code == 116)
	{ 
		theEvent.keyCode ? theEvent.keyCode = 0 : theEvent.which = 0; 
		cancelBubble = true; 
		if (e && e.preventDefault) 
			e.preventDefault(); 
		else
			window.event.returnValue = false;		
		return false; 
	} 	
}

document.oncontextmenu = function(e)
{
	return false;
}


g_CntTitle = 0;
function refreshTitle()
{
	g_CntTitle ++;
	if (0 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = ".";    
	}
	else if (1 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = "..";    
	}
	else if (2 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = "...";       
	}
	else if (3 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = "....";       
	}
	else if (4 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = ".....";       
	}
	else if (5 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = "......";       
	} 
	else if (6 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = ".......";       
	}  	 	  
	else if (7 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = "........";       
	} 
	else if (8 == g_CntTitle%10)
	{
	    document.getElementById('device_cheing').innerHTML = ".........";       
	}
	else 
	{
	    document.getElementById('device_cheing').innerHTML = "..........";       
	}  	  	 		  	
	
	    
}

function LoadFrame()
{
	TimerHandle = setInterval("requestCgi()", 5000);
	TimerHandle1 = setInterval("refreshTitle()", 500);
}

</script>

<body onload="LoadFrame();" >
<div class = "divCenter">
  <table  height="5" border="0" cellpadding="0" cellspacing="0" width="100%" align="center"> 
    <tr> 
      <td align="right" width="50%"></td>
      <td align="center"><script language="javascript">
document.write('<A href="http://' + br0Ip +':'+ httpport +'/login.asp"><font style="font-size: 13px;"  color="#000000">返回登录页面</FONT></A>');
</script></td> 
    </tr>     
    <tr> 
      <td align="right" width="50%">设备自检中</td>
      <td align="left"><strong id="device_cheing" style="width:0%;"></strong></td> 
    </tr> 
	<tr> 
      <td colspan="2"></td> 
    </tr> 
	<tr> 
      <td align="center" colspan="2">
		<div class="graph"> 
			<strong id="bar" style="width:0%;">0%</strong> 
		</div> 
      </td> 
    </tr> 
  </table> 

</div>
</body>
</html>
