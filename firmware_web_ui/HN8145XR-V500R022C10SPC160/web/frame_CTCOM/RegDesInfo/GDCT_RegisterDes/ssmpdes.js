/* 广东的资源定义 */
var RegisterPonTimeOut = 240;
var RegisterAcsLimitTime = 120;
var RegisterPon =
{
	RegisterKey:"RegisterPon",
	Percent:"InsteadOfPercent",
	PercentDesTail:"InsteadOfPercent%",
	DefDesHtml:"终端正在向OLT注册，请等待；"
}

var RegisterPon40STimeOut=
{
	RegisterKey:"RegisterPon40STimeOut",
	Percent:"23",
	PercentDesTail:"23%",
	DefDesHtml:"终端注册OLT失败，LOID不存在，请重试。"
}

var RegisterPonTimeOut=
{
	RegisterKey:"RegisterPonTimeOut",
	Percent:"24",
	PercentDesTail:"24%",
	DefDesHtml:"终端注册OLT超时，请确认PON接入方式和宽带识别码（LOID）是否与施工单一致。如果都正常，请拨打支撑电话检查OLT的PON板卡是否正常，PON口预部署数据配置是否正常。"
}

var RegisterPonFail=
{
	RegisterKey:"RegisterPonFail",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或LOID是否输入正确（历时InsteadOfSeconds秒）。"
}

var RegisterPonFailStep2=
{
	RegisterKey:"RegisterPonFailStep2",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或LOID是否输入正确（历时InsteadOfSeconds秒）。"
}

var RegisterGetIP=
{
	RegisterKey:"RegisterGetIP",
	Percent:"25",
	PercentDesTail:"25%",
	DefDesHtml:"终端注册OLT成功。"
}

var RegAcsTimeOut=
{
	RegisterKey:"RegAcsTimeOut",
	Percent:"49",
	PercentDesTail:"49%",
	DefDesHtml:"终端注册OLT成功，获取管理地址失败。请拨打支撑电话检查终端到BRAS通道及BRAS地址池配置是否正常。",
	CallBackInfo:"LOG:ITMS_NoIP"
}

var RegisterRwanIp=
{
	RegisterKey:"RegisterRwanIp",
	Percent:"InsteadOfPercent",
	PercentDesTail:"InsteadOfPercent%",
	DefDesHtml:"终端注册OLT成功，正在获取管理地址，请等待。"
}

var RegisterRwanIpDelay=
{
	RegisterKey:"RegisterRwanIpDelay",
	Percent:"InsteadOfPercent",
	PercentDesTail:"InsteadOfPercent%",
	DefDesHtml:"终端注册OLT成功，正在获取管理地址，请等待。"
}

var RegisterITMS=
{
	RegisterKey:"RegisterITMS",
	Percent:"50",
	PercentDesTail:"50%",
	DefDesHtml:"终端注册OLT成功，获取管理地址成功。"
}

var Register1THForITMS=
{
	RegisterKey:"Register1THForITMS",
	Percent:"75",
	PercentDesTail:"75%",
	DefDesHtml:"终端注册OLT成功，获取管理地址成功，注册ITMS成功。"
}

var Register3THForITMS=
{
	RegisterKey:"Register3THForITMS",
	Percent:"100",
	PercentDesTail:"100%",
	DefDesHtml:""
}

var RegisterITMSING=
{
	RegisterKey:"RegisterITMSING",
	Percent:"InsteadOfPercent",
	PercentDesTail:"InsteadOfPercent%",
	DefDesHtml:"终端注册OLT成功，获取管理地址成功，正在向ITMS发送注册请求，请等待。"
}

var RegisterITMSPing=
{
	RegisterKey:"RegisterITMSPing",
	Percent:"71",
	PercentDesTail:"71%",
	DefDesHtml:"终端向ITMS注册失败，正在Ping上层链路是否正常，请等待。"
}

var RegisterACSResult2=
{
	RegisterKey:"RegisterACSResult2",
	Percent:"98",
	PercentDesTail:"98%",
	DefDesHtml:"终端注册OLT成功，获取管理地址成功，注册ITMS成功，下发业务失败，请重试。"
}

var ITMSTimeOutLogType="ITMS_CfgTimeout";

var RegisterStatus1 = "宽带识别码（LOID）不存在！请重试。";
var RegisterStatus1OutOfLimit = "宽带识别码（LOID）不存在！请重试。";

var RegisterStatus2 = "ITMS平台无此宽带识别码（LOID）工单存在！请重试。请拨打支撑电话检查ITMS平台是否收到该注册的宽带识别码（LOID）业务工单，检查ITMS平台录入注册终端的型号、版本、OUI是否正确。";
var RegisterStatus2OutOfLimit = "ITMS平台无此宽带识别码（LOID）工单存在！请重试。请拨打支撑电话检查ITMS平台是否收到该注册的宽带识别码（LOID）业务工单，检查ITMS平台录入注册终端的型号、版本、OUI是否正确。";

var RegisterStatus3 = "E8-C请只输入宽带识别码（LOID），密码为空！请重试。";
var RegisterStatus3OutOfLimit = "E8-C请只输入宽带识别码（LOID），密码为空！请重试。";
var RegisterStatus4 = "ITMS下发业务超时，请重试。";
var RegisterStatus5 = "已注册成功，无需再注册。";

var RegisterVoipSuccess = "终端注册OLT成功，获取管理地址成功，注册ITMS成功，下发业务成功。";
var RegisterNoVoipSuccess = "终端注册OLT成功，获取管理地址成功，注册ITMS成功，下发业务成功。";

var RegisterSuccessSvrCode = "<br>终端注册OLT成功，获取管理地址成功，注册ITMS成功，下发业务成功，完成strNewProvisioning业务下发。"; 


/* 每一个资源文件都有一个大的资源数组 */
var AllRegisterDesArray = [];
AllRegisterDesArray["RegisterPon"] = RegisterPon;
AllRegisterDesArray["RegisterPonTimeOut"] = RegisterPonTimeOut;
AllRegisterDesArray["RegisterPonFail"] = RegisterPonFail;
AllRegisterDesArray["RegisterGetIP"] = RegisterGetIP;
AllRegisterDesArray["RegAcsTimeOut"] = RegAcsTimeOut;
AllRegisterDesArray["RegisterRwanIp"] = RegisterRwanIp;
AllRegisterDesArray["RegisterRwanIpDelay"] = RegisterRwanIpDelay;
AllRegisterDesArray["RegisterITMS"] = RegisterITMS;
AllRegisterDesArray["Register1THForITMS"] = Register1THForITMS;
AllRegisterDesArray["Register2THForITMSNullSrvCode"] = Register2THForITMSNullSrvCode;
AllRegisterDesArray["Register2THForITMSSrvCode"] = Register2THForITMSSrvCode;
AllRegisterDesArray["Register3THForITMS"] = Register3THForITMS;
AllRegisterDesArray["RegisterITMSING"] = RegisterITMSING;
AllRegisterDesArray["RegisterITMSPing"] = RegisterITMSPing;
AllRegisterDesArray["RegisterACSResult2"] = RegisterACSResult2;

function GetServerTypeByKey(ServerKey)
{
	if(ServerKey.toUpperCase()=="IPTV" || ServerKey.toUpperCase()== "ITV")
	{
		return "ITV";
	}
	else if(ServerKey.toUpperCase()=="INTERNET")
	{          		
		return "宽带";            			
	}
	else if(ServerKey.toUpperCase()=="VOICE" || ServerKey.toUpperCase()=="VOIP")
	{
		return "语音";	           		
	}
	else if(ServerKey.toUpperCase()=="OTHER")
	{
		return "其它";	       		
	}
	else
	{
		return ServerKey;	
	}
}

function GetServerFinalyDesInfoForSpecial(StepKey,prograssPercent)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//注册接口信息
	};
	
	if (StepKey < "1" )
	{
		RegInfo.PercentNum = 75;
		RegInfo.PercentDescribe="75%";
		RegInfo.RegResult  = "终端注册OLT成功，获取管理地址成功，注册ITMS成功。"; 
	}
	else if (StepKey == "1")
	{
		RegInfo.PercentNum = prograssPercent;
		RegInfo.PercentDescribe=prograssPercent+"%";
		RegInfo.RegResult  = "终端注册OLT成功，获取管理地址成功，注册ITMS成功，正在下发业务，请等待。"; 
	}
	else
	{
		RegInfo.PercentNum = 100;
		RegInfo.PercentDescribe="100%";
		RegInfo.RegResult  = ""
		clearTimeout(timer);                  
	} 
	
	return RegInfo;
}

function GetServerSecondDesInfoForSpecial(StepKey,RegDiffTime)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//注册接口信息
	};
	
	//超时时间为4分钟，客户要求和规范一致。
	var prograssPercent = parseInt(76+(23*RegDiffTime)/(6*60));
	prograssPercent = (prograssPercent > 98) ? 98:prograssPercent
			
	if(RegDiffTime > 240)
	{
		RegInfo.PercentNum = 99;
		RegInfo.PercentDescribe="99%";
		RegInfo.RegResult  = "ITMS下发业务超时，请重试。" ;
		RegInfo.CallBackInfo="ITMS_CfgTimeout";
	}
	else
	{
		if (StepKey < 1 )
		{
			RegInfo.PercentNum = 75;
			RegInfo.PercentDescribe="75%";
			RegInfo.RegResult  = "终端注册OLT成功，获取管理地址成功，注册ITMS成功。";
		}
		else
		{			
			RegInfo.PercentNum = prograssPercent;
			RegInfo.PercentDescribe=prograssPercent+"%";
			RegInfo.RegResult  = "终端注册OLT成功，获取管理地址成功，注册ITMS成功，正在下发业务，请等待。";                           
		}
	}
	
	return RegInfo;
}

function GetRegPonFailInfoCus(LoidAuthFlag, DiffTime, HelpNum)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//封装接口中需要特殊处理的部分信息
	};
	
	/*广东*/
	if(1 == LoidAuthFlag && DiffTime > 40)
	{
		RegInfo.IsShowPercentin = true;
		RegInfo.PercentNum = 23;
		RegInfo.PercentDescribe = "23%";
		RegInfo.RegResult = "终端注册OLT失败，宽带识别码（LOID）不存在，请重试。" ;
		RegInfo.CallBackInfo = "LOG:OLT_Fail";
	}
	else if(GetDateTimeDiff() > 240)
	{
		RegInfo.IsShowPercentin = true;
		RegInfo.PercentNum = 24;
		RegInfo.PercentDescribe = "24%";
		RegInfo.RegResult = "终端注册OLT超时，请确认PON接入方式和宽带识别码（LOID）是否与施工单一致。如果都正常，请拨打支撑电话检查OLT的PON板卡是否正常，PON口预部署数据配置是否正常。" ;
		RegInfo.CallBackInfo = "LOG:OLT_TimeOut";
	}
	else
	{
		RegInfo.CallBackInfo = "function";
	}
	
	return RegInfo;
}

function GetDesForStatus5(DiffTime)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//封装接口中需要特殊处理的部分信息
	};
	
	if( DiffTime > 120 )
	{
		RegInfo.PercentNum = 71;
		RegInfo.PercentDescribe = "71%";;
		RegInfo.RegResult = "终端向ITMS注册失败，正在Ping上层链路是否正常，请等待。" ;
		RegInfo.CallBackInfo ="LOG:ITMS_RegFail";			
	}
	else
	{
		var prograssPercent = parseInt(51+(20*DiffTime)/(2*60));
		prograssPercent = (prograssPercent > 70)?70:prograssPercent;
		RegInfo.PercentNum = prograssPercent;
		RegInfo.PercentDescribe = prograssPercent+"%";
		RegInfo.RegResult ="终端注册OLT成功，获取管理地址成功，正在向ITMS发送注册请求，请等待。";					
	}
	
	return RegInfo;
}

function GetDesForStatus6(DiffTime)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//封装接口中需要特殊处理的部分信息
	};
	
	RegInfo.PercentNum = 72 ;
	RegInfo.PercentDescribe = "72%";
	RegInfo.RegResult = "终端向ITMS注册失败，正在Ping上层链路是否正常，请等待。";	
	RegInfo.CallBackInfo ="LOG:ITMS_RegFail";
	return RegInfo;
}


function GetDesForStatus7(DiffTime,PingCount)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//封装接口中需要特殊处理的部分信息
	};
	
	RegInfo.CallBackInfo ="LOG:ITMS_RegFail";
	if(PingCount > 0)
	{              
		RegInfo.PercentNum = 74;
		RegInfo.PercentDescribe = "74%";
		RegInfo.RegResult = "终端注册OLT成功，获取管理地址成功，注册ITMS失败，上层链路正常。请拨打支撑电话查询ITMS平台终端是否在线，并重新注册，跟踪终端注册报文。";
	}
	else
	{			
		RegInfo.PercentNum = 73;
		RegInfo.PercentDescribe = "73%";
		RegInfo.RegResult = "终端注册OLT成功，获取管理地址成功，注册ITMS失败，上层链路不通。请拨打支撑电话检查终端到ITMS路由是否正常，ITMS平台是否正常。";     	
	}    
	
	return RegInfo;
}


function GetDesForOpticCheck(lastPercent)
{
	var RegInfo = {
		PercentNum: 0,	//百分比数字
		PercentDescribe: "",	//百分比描述
		RegResult: "",	//注册接口信息
		IsShowPercentin:"",
		CallBackInfo: ""	//封装接口中需要特殊处理的部分信息
	};
	
	RegInfo.CallBackInfo ="LOG:OLT_Fail";
	
	if (lastPercent != null && lastPercent != "" && lastPercent != "0")/* 存在光路故障 */
	{
		RegInfo.PercentNum = lastPercent;
		RegInfo.PercentDescribe = lastPercent + "%";
		RegInfo.RegResult = '终端注册光信号丢失，请检查光线路的光功率是否正常，终端光模块是否正常。<font style="color: red;">请点击返回，重新注册。</font>';
	}
	
	return RegInfo;
}


/* 光功率不在合法范围则认为异常，正常的控制范围，GPON:(-31, -8)  EPON(-31, -3) */
function IsOpticPowerEorrorForGDCheck(AccessMode, OpticInfo)
{
	if (AccessMode.toUpperCase() == 'GPON')
	{ 
		if(parseInt(OpticInfo) > -31 && parseInt(OpticInfo) < -8)
		{
			return false;
		}
		
		return true;
	}
	else if (AccessMode.toUpperCase() == 'EPON') /* EPON */	
	{ 
		if(parseInt(OpticInfo) > -31 && parseInt(OpticInfo) < -3)
		{
			return false;
		}
		
		return true;
	}
	
    return true;
}



