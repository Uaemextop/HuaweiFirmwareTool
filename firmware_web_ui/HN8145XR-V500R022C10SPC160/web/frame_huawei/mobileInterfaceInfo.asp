function() {
    function lteBasicInfo(regitstedNetwork, serviceStatus, serviceDomain, roamStatus, simStatus, systemMode, sysSubMode, lteBand, signalQuality, simState, wanState) {
        this.regitstedNetwork = regitstedNetwork;
        this.serviceStatus = serviceStatus;
        this.serviceDomain = serviceDomain;
        this.roamStatus = roamStatus;
        this.simStatus = simStatus;
        this.systemMode = systemMode;
        this.sysSubMode = sysSubMode;
        this.lteBand = lteBand;
        this.signalQuality = signalQuality;
        this.simState = simState;
        this.wanState = wanState;
    }

    var resultInfo = <%WEB_GetLteBasicInfo();%>;
    return resultInfo;
}
