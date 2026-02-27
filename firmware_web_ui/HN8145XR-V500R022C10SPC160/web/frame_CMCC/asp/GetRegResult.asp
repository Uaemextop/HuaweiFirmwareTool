function(){
	function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum, X_HW_RmsRegType)
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
		this.X_HW_RmsRegType = X_HW_RmsRegType;
	}  
		
	var ResultStatusInfo =  <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|Limit|Times|X_HW_TimeoutState|X_HW_InformStatus|ProvisioningCode|ServiceNum|X_HW_RmsRegType, stResultInfo);%>;
	return ResultStatusInfo[0];
}
