(function(){
	function ResultStatusSt(domain, Result, Status)
	{
		this.domain = domain;
		this.Result = Result;
		this.Status  = Status;
	}
	var ResultStatusInfo =  <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, ResultStatusSt);%>;
	return ResultStatusInfo[0];
})();
