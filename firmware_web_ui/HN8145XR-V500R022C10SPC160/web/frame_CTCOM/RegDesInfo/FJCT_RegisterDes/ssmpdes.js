/* 通用的资源定义 */
var RegisterPonTimeOut = 300;
var RegisterAcsLimitTime = 300;

var RegisterPon=
{
	RegisterKey:"RegisterPon",
	IsShowPercentin:"TRUE",
	Percent:"30",
	PercentDesTail:"30%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端正在向OLT发起注册。",
	LowOpticDes:"终端正在向OLT发起注册"+"（光功率过低）。"
}

var RegisterPonTimeOut=
{
	RegisterKey:"RegisterPonTimeOut",
	IsShowPercentin:"FALSE",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"在OLT上注册失败，请检查光纤是否已正常连接、宽带识别码（LOID）和密码是否正确，如无法解决请联系客户经理或拨打HelpTelNum（历时InsteadOfSeconds秒）。"
}

var RegisterPonFail=
{
	RegisterKey:"RegisterPonFail",
	IsShowPercentin:"FALSE",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或宽带识别码（LOID）是否输入正确（历时InsteadOfSeconds秒）。"
}

var RegisterGetIP=
{
	RegisterKey:"RegisterGetIP",
	Percent:"30",
	PercentDesTail:"30%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端在OLT已注册成功，下一步是终端向ITMS平台发起注册。"
}

var RegAcsTimeOut=
{
	RegisterKey:"RegAcsTimeOut",
	IsShowPercentin:"FALSE",
	Percent:"0",
	PercentDesTail:"",
	DefDesHtml:"终端到ITMS的通道不通，请找支撑经理处理（历时InsteadOfSeconds秒）。",
	CallBackInfo:"LOG:ITMS_NoIP"
}

var RegisterRwanIp=
{
	RegisterKey:"RegisterRwanIp",
	Percent:"30",
	PercentDesTail:"30%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端在OLT已注册成功，下一步是终端向ITMS平台发起注册。"
}

var RegisterRwanIpDelay=
{
	RegisterKey:"RegisterRwanIpDelay",
	Percent:"30",
	PercentDesTail:"30%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端在OLT已注册成功，下一步是终端向ITMS平台发起注册。"
}

var RegisterITMS=
{
	RegisterKey:"RegisterITMS",
	Percent:"30",
	PercentDesTail:"30%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端在OLT已注册成功，下一步是终端向ITMS平台发起注册。"
}

var Register1THForITMS=
{
	RegisterKey:"Register1THForITMS",
	Percent:"50",
	PercentDesTail:"50%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端在ITMS平台注册成功，下一步是ITMS平台下发数据。"
}

var Register2THForITMSNullSrvCode=
{
	RegisterKey:"Register2THForITMSNullSrvCode",
	Percent:"60",
	PercentDesTail:"60%（历时InsteadOfSeconds秒）",
	DefDesHtml:"ITMS平台正在进行数据下发，请勿下电或拔插光纤。"
}

var Register2THForITMSSrvCode=
{
	RegisterKey:"Register2THForITMSSrvCode",
	Percent:"60",
	PercentDesTail:"60%（历时InsteadOfSeconds秒）",
	DefDesHtml:"ITMS平台正在进行数据下发，请勿下电或拔插光纤。"
}

var Register3THForITMS=
{
	RegisterKey:"Register3THForITMS",
	Percent:"100",
	PercentDesTail:"100%（历时InsteadOfSeconds秒）",
	DefDesHtml:""
}

var RegisterACSResult2=
{
	RegisterKey:"RegisterACSResult2",
	Percent:"0",
	PercentDesTail:"",
	DefDesHtml:"ITMS平台业务未下发或业务下发异常，请找支撑经理处理（历时InsteadOfSeconds秒）。"
}

var ITMSTimeOutLogType="ITMS_Timeout";

var RegisterStatus1 = "输入的PASSWORD（密码）不正确，请核实后重新注册（剩余尝试次数：LeftRegTime）（历时InsteadOfSeconds秒）。";
var RegisterStatus1OutOfLimit = "输入的PASSWORD（密码）不正确，注册失败，请支撑经理处理（历时InsteadOfSeconds秒）。";

var RegisterStatus2 = "输入的宽带识别码（LOID）在ITMS平台不存在，注册失败，请核实后重新注册！请重试（剩余尝试次数：LeftRegTime）（历时InsteadOfSeconds秒）。";
var RegisterStatus2OutOfLimit = "输入的宽带识别码（LOID）在ITMS平台不存在，注册失败，请找支撑经理处理（历时InsteadOfSeconds秒）。";

var RegisterStatus3 = "身份证与宽带账号不匹配！请重试（剩余尝试次数：LeftRegTime）（历时InsteadOfSeconds秒）。";
var RegisterStatus3OutOfLimit = "身份证与宽带账号不匹配！注册失败，请联系10000号（历时InsteadOfSeconds秒）。";
var RegisterStatus4 = "注册超时！请检查线路后重试（历时InsteadOfSeconds秒）。";
var RegisterStatus5 = "该终端已在ITMS平台成功注册过，请找支撑经理处理后再重新注册（历时InsteadOfSeconds秒）。";
var RegisterVoipSuccess = "<br>ITMS平台数据下发成功，共下发了宽带、语音、iTV三个业务，欢迎使用天翼网关。";
var RegisterNoVoipSuccess = "<br>ITMS平台数据下发成功，共下发了宽带、iTV两个业务，欢迎使用天翼网关。";
var RegisterSuccessSvrCode = "<br>ITMS平台数据下发成功，共下发了strNewProvisioning[strNum]个业务，欢迎使用天翼网关。"; 

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
AllRegisterDesArray["RegisterACSResult2"] = RegisterACSResult2;

function GetServerTypeByKey(ServerKey)
{
	if(ServerKey.toUpperCase()=="IPTV" || ServerKey.toUpperCase()== "ITV")
	{
		return "iTV";
	}
	else if(ServerKey.toUpperCase()=="INTERNET")
	{                  
		return "上网";                        
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

function GetServerTotalNum(ServerArray)
{
	var strNum="";
	if (0 == ServerArray.length)
	{
		strNum = "零";
	}
	else if (1 == ServerArray.length)
	{
		strNum = "一";
	}
	else if (2 == ServerArray.length)
	{
		strNum = "二";
	}
	else if (3 == ServerArray.length)
	{
		strNum = "三";
	}
	else if (4 == ServerArray.length)
	{
		strNum = "四";
	}
	else
	{
		strNum = "多";
	}
	
	return strNum;
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
	
	if (GetDateTimeDiff() > 300)
	{
		RegInfo.PercentNum = 0;
		RegInfo.PercentDescribe="";
		RegInfo.RegResult  = "在OLT上注册失败，请检查光纤是否已正常连接、宽带识别码（LOID）和密码是否正确，如无法解决请联系客户经理或拨打"+HelpNum+""+" （历时"+DiffTime+"秒）。" ;	
		RegInfo.CallBackInfo = "LOG:OLT_Fail";
	}		
	else
	{
		RegInfo.CallBackInfo = "function";
	}
	
	return RegInfo;
}


