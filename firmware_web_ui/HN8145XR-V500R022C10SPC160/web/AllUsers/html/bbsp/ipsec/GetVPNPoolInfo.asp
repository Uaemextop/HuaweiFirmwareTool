function() {
  var VPNPoolInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.AddressPool.{i}, Name|MinAddress|MaxAddress|SubnetMask|DNSServer, stVPNPoolInfos);%>;
  function stVPNPoolInfos(domain, Name, MinAddress, MaxAddress, SubnetMask, DNSServer) {
      this.domain = domain;
      this.Name = Name;
      this.MinAddress = MinAddress;
      this.MaxAddress = MaxAddress;
      this.SubnetMask = SubnetMask;
      this.DNSServer = DNSServer;
  }
  
  function GetVPNPoolInfos() {
      return VPNPoolInfos;
  }
  
  return GetVPNPoolInfos();
}