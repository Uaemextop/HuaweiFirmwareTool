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
var refreshData = 1;
var FskStatus = '';
var xmlHttp = false;

var ctrgflag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';

function IsFF()
{          
	return navigator.userAgent.indexOf("Firefox")!=-1;      
}

function GetFskStatus()
{
	   $.ajax({
            type : "GET",
            async : true,
            cache : false,
            url : "getFskStatus.asp",
            success : function(data) {
            	FskStatus = data;
            },
			error : function(e) {
            	FskStatus = "";
            }
        });
}

function CheckHeartAllWithoutFF()
{
	   $.ajax({
            type : "GET",
            async : true,
            cache : false,
            url : "../html/ssmp/common/refreshTime.asp",
            success : function(data) {
            
            	refreshData = data;
			    if ( refreshData != 1)
				{
					if (ctrgflag == 1)
					{
						if((FskStatus == 'start') && (IsMaintWan !=1)){
							clearInterval(TimerHandle);
							var url = 'http://' + br0Ip + '/cgi-bin/luci';
							top.location.replace(url);
						} else {
							clearInterval(TimerHandle);
							top.location.replace("/login.asp");
						}
					}
					else
					{
						clearInterval(TimerHandle);
						window.location.replace("/login.asp");
					}	
				}
            }
        });
}

function handleResponse()
{
	if(xmlHttp.readyState == 4 && xmlHttp.status==200)
	{
		var HeartStatus = xmlHttp.responseText;
		if (HeartStatus.substr(0,1) == "1") 
		{
			xmlHttp = null;
			return true;
		} 
		
		xmlHttp = null;
		if (ctrgflag == 1)
		{
			if((FskStatus == 'start') && (IsMaintWan !=1))
			{
				clearInterval(TimerHandle);
				var url = 'http://' + br0Ip + '/cgi-bin/luci';
				top.location.replace(url);
			}

		}
		else
		{
			clearInterval(TimerHandle);
			window.location.replace("/login.asp");
		}	
		return true;
	}
}

function CheckHeartStatus()
{
	try 
	{
		xmlHttp = new XMLHttpRequest();
	}
	catch (trymicrosoft) 
	{
	 	try 
		{
			xmlHttp = new ActiveXObject("Msxml2.XMLHTTP");
		} 
		catch (othermicrosoft) 
		{
			try 
			{
				xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
			} 
			catch (failed) 
			{ 
				xmlHttp = false;
			}
		}
	}
	
	if (!xmlHttp)
	{
		return true;
	}
	
	try
	{
	    xmlHttp.open("GET", "/html/ssmp/common/refreshTime.asp", true);
		xmlHttp.send(null);
		setTimeout("xmlHttp.onreadystatechange = handleResponse();", 3000);
	}
	catch(e)
	{
		return true;
	}
	
    return true;
}

function requestCgi()
{
	if (parent.UpgradeFlag == "0")
	{ 
		if (true == IsFF())
		{
			xmlHttp = null;
			if (ctrgflag == 1)
			{
			GetFskStatus();
			}
			CheckHeartStatus();
			//CheckHeartAllWithoutFF();
		}
		else
		{
			if (ctrgflag == 1)
			{
			GetFskStatus();
			}
			CheckHeartAllWithoutFF();
		}
	}
}

var TimerHandle = setInterval("requestCgi()", 5000);
</script>
</head>
<body onload=""> </body>
</html>
