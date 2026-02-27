function() {
    function VoiceProfileInfoSip(Domain, OutboundProxy, X_HW_SecondaryOutboundProxy, ProxyServer, X_HW_SecondaryProxyServer, RegistrarServer)
    {
        this.Domain = Domain;
        this.OutboundProxy = OutboundProxy;
        this.X_HW_SecondaryOutboundProxy = X_HW_SecondaryOutboundProxy;
        this.ProxyServer = ProxyServer;
        this.X_HW_SecondaryProxyServer = X_HW_SecondaryProxyServer;
        this.RegistrarServer = RegistrarServer;
    }

    var voiceSipInfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.SIP, OutboundProxy|X_HW_SecondaryOutboundProxy|ProxyServer|X_HW_SecondaryProxyServer|RegistrarServer, VoiceProfileInfoSip);%>;
    return voiceSipInfo;
}
