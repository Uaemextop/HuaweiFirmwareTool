function(){
	function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum, Desc)
	{
		this.domain = domain;
		this.Result = Result;
		this.Status = Status;
		this.Limits = Limits;
	 	this.Times = Times;
	 	this.RegTimerState = RegTimerState;
	    this.InformStatus	= InformStatus;
	 	this.ProvisioningCode = ProvisioningCode;
	    this.ServiceNum = ServiceNum;
		this.Desc = Desc;
	}  
		
	var ResultStatusInfo =  <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|Limit|Times|X_HW_TimeoutState|X_HW_InformStatus|ProvisioningCode|ServiceNum|Desc, stResultInfo);%>;
	return ResultStatusInfo[0];
}
