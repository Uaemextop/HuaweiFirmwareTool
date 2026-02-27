function() {
    function VoiceProfileInfoH248(Domain, CallAgent1, CallAgent2)
    {
        this.Domain = Domain;
        this.CallAgent1 = CallAgent1;
        this.CallAgent2 = CallAgent2;
    }

    var voiceH248Info = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.X_HW_H248, CallAgent1|CallAgent2, VoiceProfileInfoH248);%>;
    return voiceH248Info;
}

