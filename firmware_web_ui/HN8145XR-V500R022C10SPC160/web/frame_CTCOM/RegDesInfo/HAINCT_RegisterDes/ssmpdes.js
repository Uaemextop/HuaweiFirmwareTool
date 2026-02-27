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
	Percent:"",
	PercentDesTail:"",
	DefDesHtml:"到ITMS 的通道不通，请联系客户经理或拨打HelpTelNum（历时InsteadOfSeconds秒）。",
	CallBackInfo:"LOG:ITMS_NoIP"
}

var RegisterRwanIp=
{
	RegisterKey:"RegisterRwanIp",
	Percent:"30",
	PercentDesTail:"30%（历时InsteadOfSeconds秒）",
	DefDesHtml:"<br>注册OLT成功，正在获取管理IP。"
}


var RegisterRwanIpDelay=
{
	RegisterKey:"RegisterRwanIpDelay",
	Percent:"40",
	PercentDesTail:"40%（历时InsteadOfSeconds秒）",
	DefDesHtml:"<br>已获得管理IP，正在连接ITMS。"
}

var RegisterITMS=
{
	RegisterKey:"RegisterITMS",
	Percent:"40",
	PercentDesTail:"40%（历时InsteadOfSeconds秒）",
	DefDesHtml:"<br>已获得管理IP，正在连接ITMS。"
}

var Register1THForITMS=
{
	RegisterKey:"Register1THForITMS",
	Percent:"50",
	PercentDesTail:"50%（历时InsteadOfSeconds秒）",
	DefDesHtml:"<br>注册ITMS成功，等待ITMS平台下发业务数据。"
}

var Register2THForITMSNullSrvCode=
{
	RegisterKey:"Register2THForITMSNullSrvCode",
	Percent:"ProvisioningPercent",
	PercentDesTail:"ProvisioningPercent%（历时InsteadOfSeconds秒）",
	DefDesHtml:"<br>ITMS平台正在下发业务数据，请勿断电或拔光纤。"
}

var Register2THForITMSSrvCode=
{
	RegisterKey:"Register2THForITMSSrvCode",
	Percent:"ProvisioningPercent",
	PercentDesTail:"ProvisioningPercent%（历时InsteadOfSeconds秒）",
	DefDesHtml:"<br>ITMS平台正在下发strServiceName业务数据，请勿断电或拔光纤。"
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
	DefDesHtml:"ITMS下发业务异常！请联系客户经理或拨打HelpTelNum。"
}

var ITMSTimeOutLogType="ITMS_Timeout";

var RegisterStatus1 = "在ITMS上注册失败！请检查宽带识别码（LOID）和密码是否正确，如无法解决请联系客户经理或拨打10000。";
var RegisterStatus1OutOfLimit = "在ITMS上注册失败！请3分钟后重试，如无法解决请联系客户经理或拨打10000。";

var RegisterStatus2 = "在ITMS上注册失败！请检查宽带识别码（LOID）和密码是否正确，如无法解决请联系客户经理或拨打10000。";
var RegisterStatus2OutOfLimit = "在ITMS上注册失败！请3分钟后重试，如无法解决请联系客户经理或拨打10000。";

var RegisterStatus3 = "在ITMS上注册失败！请检查宽带识别码（LOID）和密码是否正确，如无法解决请联系客户经理或拨打10000。";
var RegisterStatus3OutOfLimit = "在ITMS上注册失败！请3分钟后重试，如无法解决请联系客户经理或拨打10000。";
var RegisterStatus4 = "在ITMS上注册超时！请检查线路后重试，如无法解决请联系客户经理或拨打10000。";
var RegisterStatus5 = "已经在ITMS注册成功，无需再注册。";
var RegisterVoipSuccess = "<br>ITMS平台业务数据下发成功，为确保各项业务正常生效，请人工重启天翼网关！";
var RegisterNoVoipSuccess = "<br>ITMS平台业务数据下发成功，为确保各项业务正常生效，请人工重启天翼网关！";

var RegisterSuccessSvrCode = "<br>ITMS平台数据下发成功，共下发了strNewProvisioning[strNum]个业务，为确保各项业务正常生效，请人工重启天翼网关！"; 

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




