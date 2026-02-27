/* 四川的资源定义 */
var RegisterPonTimeOut = 120;
var RegisterAcsLimitTime = 300;
var RegisterPon=
{
	RegisterKey:"RegisterPon",
	Percent:"30",
	PercentDesTail:"30%",
	DefDesHtml:"终端正在注册OLT。",
	LowOpticDes:"终端正在注册OLT"+"（光功率过低）。"
}

var RegisterPonTimeOut=
{
	RegisterKey:"RegisterPonTimeOut",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"注册OLT失败!请检查线路后重试。"
}

var RegisterPonFail=
{
	RegisterKey:"RegisterPonFail",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"注册OLT失败，请检查终端收光功率是否正常、宽带识别码（LOID）和PASSWORD是否正确。"
}

var RegisterPonFailStep2=
{
	RegisterKey:"RegisterPonFailStep2",
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"ITMS业务下发失败，请联系10000号。"
}

var RegisterGetIP=
{
	RegisterKey:"RegisterGetIP",
	Percent:"30",
	PercentDesTail:"30%",
	DefDesHtml:"终端注册OLT已成功，下一步将获取管理地址。"
}

var RegAcsTimeOut=
{
	RegisterKey:"RegAcsTimeOut",
	Percent:"0",
	PercentDesTail:"",
	DefDesHtml:"终端获取ITMS管理通道失败，请联系HelpTelNum。"
	CallBackInfo:"LOG:ITMS_NoIP"
}

var RegisterRwanIp=
{
	RegisterKey:"RegisterRwanIp",
	Percent:"40",
	PercentDesTail:"40%",
	DefDesHtml:"终端正在获取管理地址。"
}


var RegisterRwanIpDelay=
{
	RegisterKey:"RegisterRwanIpDelay",
	Percent:"40",
	PercentDesTail:"40%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端已获取管理地址成功，下一步将注册ITMS平台。"
}

var RegisterITMS=
{
	RegisterKey:"RegisterITMS",
	Percent:"40",
	PercentDesTail:"40%（历时InsteadOfSeconds秒）",
	DefDesHtml:"终端已获取管理地址成功，下一步将注册ITMS平台。"
}

var Register1THForITMS=
{
	RegisterKey:"Register1THForITMS",
	Percent:"50",
	PercentDesTail:"50%",
	DefDesHtml:"终端注册ITMS平台成功，下一步ITMS平台将下发数据。"
}

var Register2THForITMSNullSrvCode=
{
	RegisterKey:"Register2THForITMSNullSrvCode",
	Percent:"60",
	PercentDesTail:"60%",
	DefDesHtml:"ITMS平台正在下发数据，请勿下电或拔插光纤。"
}

var Register2THForITMSSrvCode=
{
	RegisterKey:"Register2THForITMSSrvCode",
	Percent:"60",
	PercentDesTail:"60%",
	DefDesHtml:"ITMS平台正在下发数据，请勿下电或拔插光纤。"
}


var Register3THForITMS=
{
	RegisterKey:"Register3THForITMS",
	Percent:"100",
	PercentDesTail:"100%",
	DefDesHtml:""
}

var RegisterACSResult2=
{
	RegisterKey:"RegisterACSResult2",
	Percent:"0",
	PercentDesTail:"",
	DefDesHtml:"注册ITMS平台成功，ITMS平台业务未下发或业务下发异常，请联系HelpTelNum。"
}


var ITMSTimeOutLogType="ITMS_Timeout";

var RegisterStatus1 = "Password不存在，请重试（剩余尝试次数：LeftRegTime）。";
var RegisterStatus1OutOfLimit = "Password不存在，注册失败，请联系10000号。";

var RegisterStatus2 = "宽带识别码（LOID）不存在，请重试（剩余尝试次数：LeftRegTime）。";
var RegisterStatus2OutOfLimit = "宽带识别码（LOID）不存在，注册失败，请联系10000号。";

var RegisterStatus3 = "宽带识别码（LOID）和Password不匹配，请重试（剩余尝试次数：LeftRegTime）。";
var RegisterStatus3OutOfLimit = "宽带识别码（LOID）和Password不匹配，注册失败，请联系10000号。";
var RegisterStatus4 = "注册超时！请检查线路后重试。";
var RegisterStatus5 = "设备已注册，无需再注册。";

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
		RegInfo.CallBackInfo = "LOG:OLT_TimeOut";
		RegInfo.RegResult  = "注册超时!请检查线路后重试。" ;							
	}		
	else
	{
		RegInfo.CallBackInfo = "function";
	}
	
	return RegInfo;
}

