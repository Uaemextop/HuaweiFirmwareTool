function() {
    function DSLInfo(domain, UpstreamCurrRate, DownstreamCurrRate, UpstreamMaxRate, DownstreamMaxRate) {
        this.domain = domain;
        this.UpstreamCurrRate = UpstreamCurrRate;
        this.DownstreamCurrRate = DownstreamCurrRate;
        this.UpstreamMaxRate = UpstreamMaxRate;
        this.DownstreamMaxRate = DownstreamMaxRate;
    }

    var DSLInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANDSLInterfaceConfig,UpstreamCurrRate|DownstreamCurrRate|UpstreamMaxRate|DownstreamMaxRate,DSLInfo);%>;
    return DSLInfos;
}
