<%SendWebHeadStr(); %>
<title><% multilang("12" "LANG_ETHERNET_WAN"); %></title>
<script language="javascript">
var initConnectMode;
var pppConnectStatus=0;
var dgwstatus;
var gtwy;
var interfaceInfo = '';
var gtwyIfc ='';
var gwInterface=0;
var ipver=1;
var mapFmrSelect = 0;
function pppTypeSelection()
{
 if ( document.ethwan.pppConnectType.selectedIndex == 2) {
  document.ethwan.pppIdleTime.value = "";
  disableTextField(document.ethwan.pppIdleTime);
 }
 else {
  if (document.ethwan.pppConnectType.selectedIndex == 1) {
   enableTextField(document.ethwan.pppIdleTime);
  }
  else {
   document.ethwan.pppIdleTime.value = "";
   disableTextField(document.ethwan.pppIdleTime);
  }
 }
}
function checkDefaultGW() {
 with (document.forms[0]) {
  if (droute[0].checked == false && droute[1].checked == false && gwStr[0].checked == false && gwStr[1].checked == false) {
   alert('A default gateway has to be selected.');
   return false;
  }
  if (droute[1].checked == true) {
   if (gwStr[0].checked == true) {
    if (isValidIpAddress(dstGtwy.value, "Default Gateway IP Address") == false)
     return false;
   }
  }
 }
 return true;
}
function applyCheck(obj)
{
 if (checkDefaultGW()==false)
  return false;
 if ( document.ethwan.adslConnectionMode.value == 2 ) {
  if (document.ethwan.pppUserName.value=="") {
   alert('<% multilang("2037" "LANG_PPP_USER_NAME_CANNOT_BE_EMPTY"); %>');
   document.ethwan.pppUserName.focus();
   return false;
  }
  if (includeSpace(document.ethwan.pppUserName.value)) {
   alert('<% multilang("2038" "LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PPP_USER_NAME"); %>');
   document.ethwan.pppUserName.focus();
   return false;
  }
  if (checkString(document.ethwan.pppUserName.value) == 0) {
   alert('<% multilang("2039" "LANG_INVALID_PPP_USER_NAME"); %>');
   document.ethwan.pppUserName.focus();
   return false;
  }
  if (document.ethwan.pppPassword.value=="") {
   alert('<% multilang("2040" "LANG_PPP_PASSWORD_CANNOT_BE_EMPTY"); %>');
   document.ethwan.pppPassword.focus();
   return false;
  }
  if (includeSpace(document.ethwan.pppPassword.value)) {
    alert('<% multilang("2041" "LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PPP_PASSWORD"); %>');
   document.ethwan.pppPassword.focus();
   return false;
  }
  if (checkString(document.ethwan.pppPassword.value) == 0) {
    alert('<% multilang("2042" "LANG_INVALID_PPP_PASSWORD"); %>');
    document.ethwan.pppPassword.focus();
    return false;
  }
  if (document.ethwan.pppConnectType.selectedIndex == 1) {
   if (document.ethwan.pppIdleTime.value <= 0) {
    alert('<% multilang("2043" "LANG_INVALID_PPP_IDLE_TIME"); %>');
    document.ethwan.pppIdleTime.focus();
    return false;
   }
  }
 }
 if (<% checkWrite("IPv6Show"); %>) {
  if(document.ethwan.IpProtocolType.value & 1){
   if ( document.ethwan.adslConnectionMode.selectedIndex == 1 ) {
    if (document.ethwan.ipMode[0].checked) {
     if ( document.ethwan.ipUnnum.disabled || ( !document.ethwan.ipUnnum.disabled && !document.ethwan.ipUnnum.checked )) {
      if (!checkHostIP(document.ethwan.ip, 1))
       return false;
      if (document.ethwan.remoteIp.visiblity == "hidden") {
       if (!checkHostIP(document.ethwan.remoteIp, 1))
       return false;
      }
      if (document.ethwan.adslConnectionMode.selectedIndex == 1 && !checkNetmask(document.ethwan.netmask, 1))
       return false;
     }
    }
   }
  }
 }
 if (<% checkWrite("IPv6Show"); %>) {
  if (document.ethwan.adslConnectionMode.value != 0
   && (document.ethwan.IpProtocolType.value & 2)) {
   if(document.ethwan.AddrMode.value == '16') {
    if(document.ethwan.iana.checked == false && document.ethwan.iapd.checked == false ) {
     alert('<% multilang("2045" "LANG_PLEASE_SELECT_IANA_OR_IAPD"); %>');
     document.ethwan.iana.focus();
     return false;
    }
   }
   if(document.ethwan.AddrMode.value == '2') {
    if(document.ethwan.Ipv6Addr.value == "" || document.ethwan.Ipv6PrefixLen.value == "") {
     alert('<% multilang("2046" "LANG_PLEASE_INPUT_IPV6_ADDRESS_AND_PREFIX_LENGTH"); %>');
     document.ethwan.Ipv6Addr.focus();
     return false;
    }
    if(document.ethwan.Ipv6Addr.value != ""){
     if (! isGlobalIpv6Address( document.ethwan.Ipv6Addr.value) ){
      alert('<% multilang("2047" "LANG_INVALID_IPV6_ADDRESS"); %>');
      document.ethwan.Ipv6Addr.focus();
      return false;
     }
     var prefixlen= getDigit(document.ethwan.Ipv6PrefixLen.value, 1);
     if (prefixlen > 128 || prefixlen <= 0) {
      alert('<% multilang("2048" "LANG_INVALID_IPV6_PREFIX_LENGTH"); %>');
      document.ethwan.Ipv6PrefixLen.focus();
      return false;
     }
    }
    if(document.ethwan.Ipv6Gateway.value != "" ){
     if (! isUnicastIpv6Address( document.ethwan.Ipv6Gateway.value) ){
      alert('<% multilang("2049" "LANG_INVALID_IPV6_GATEWAY_ADDRESS"); %>');
      document.ethwan.Ipv6Gateway.focus();
      return false;
     }
    }
    if(document.ethwan.Ipv6Dns1.value != "" ){
     if (! isIpv6Address( document.ethwan.Ipv6Dns1.value) ){
      alert('<% multilang("2050" "LANG_INVALID_PRIMARY_IPV6_DNS_ADDRESS"); %>');
      document.ethwan.Ipv6Dns1.focus();
      return false;
     }
    }
    if(document.ethwan.Ipv6Dns2.value != "" ){
     if (! isIpv6Address( document.ethwan.Ipv6Dns2.value) ){
      alert('<% multilang("2051" "LANG_INVALID_SECONDARY_IPV6_DNS_ADDRESS"); %>');
      document.ethwan.Ipv6Dns2.focus();
      return false;
     }
    }
   }
   else if ( document.ethwan.dnsV6Mode[1].checked ) {
    if(document.ethwan.Ipv6Dns1.value != "" ){
     if (! isUnicastIpv6Address( document.ethwan.Ipv6Dns1.value) ){
      alert('<% multilang("2050" "LANG_INVALID_PRIMARY_IPV6_DNS_ADDRESS"); %>');
      document.ethwan.Ipv6Dns1.focus();
      return false;
     }
    }
    if(document.ethwan.Ipv6Dns2.value != "" ){
     if (! isUnicastIpv6Address( document.ethwan.Ipv6Dns2.value) ){
      alert('<% multilang("2051" "LANG_INVALID_SECONDARY_IPV6_DNS_ADDRESS"); %>');
      document.ethwan.Ipv6Dns2.focus();
      return false;
     }
    }
   }
   else{
    document.ethwan.Ipv6Addr.value = "";
    document.ethwan.Ipv6PrefixLen.value = "";
    document.ethwan.Ipv6Gateway.value = "";
    document.ethwan.Ipv6Dns1.value = "";
    document.ethwan.Ipv6Dns2.value = "";
   }
   if (<% checkWrite("6rdShow"); %>) {
    if (document.ethwan.adslConnectionMode.value == 8)
    {
     if(document.ethwan.SixrdBRv4IP.value == ""){
      alert('<% multilang("2052" "LANG_INVALID_6RD_BOARD_ROUTER_V4IP_ADDRESS"); %>');
      document.ethwan.SixrdBRv4IP.focus();
      return false;
     }
     if(document.ethwan.SixrdIPv4MaskLen.value == ""){
      alert('<% multilang("2053" "LANG_INVALID_6RD_IPV4_MASK_LENGTH"); %>');
      document.ethwan.SixrdIPv4MaskLen.focus();
      return false;
     }
     if(document.ethwan.SixrdPrefix.value == ""){
      alert('<% multilang("2054" "LANG_INVALID_6RD_PREFIX_ADDRESS"); %>');
      document.ethwan.SixrdPrefix.focus();
      return false;
     }
     if(document.ethwan.SixrdPrefixLen.value == ""){
      alert('<% multilang("2055" "LANG_INVALID_6RD_PREFIX_LENGTH"); %>');
      document.ethwan.SixrdPrefixLen.focus();
      return false;
     }
    }
    else{
     document.ethwan.SixrdBRv4IP.value = "";
     document.ethwan.SixrdIPv4MaskLen.value = "";
     document.ethwan.SixrdPrefix.value = "";
     document.ethwan.SixrdPrefixLen.value = "";
    }
   }
   if (<% checkWrite("DSLiteShow"); %>) {
    if(document.ethwan.dslite_enable.checked == true)
    {
     if (document.ethwan.dslite_aftr_mode.value == 1)
     {
      if (! isIpv6Address( document.ethwan.dslite_aftr_hostname.value) )
                           {
       alert('Invalid Aftr host IPv6 Address');
       document.ethwan.dslite_aftr_hostname.focus();
       return false;
          }
     }
    }
   }
  }
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function setPPPConnected()
{
 pppConnectStatus = 1;
}
function dnsModeClicked()
{
 if ( document.ethwan.dnsMode[0].checked )
 {
  disableTextField(document.ethwan.dns1);
  disableTextField(document.ethwan.dns2);
 }
 if ( document.ethwan.dnsMode[1].checked )
 {
  enableTextField(document.ethwan.dns1);
  enableTextField(document.ethwan.dns2);
 }
}
function dnsModeV6Clicked()
{
 if ( document.ethwan.dnsV6Mode[0].checked )
 {
  disableTextField(document.ethwan.Ipv6Dns1);
  disableTextField(document.ethwan.Ipv6Dns2);
 }
 if ( document.ethwan.dnsV6Mode[1].checked )
 {
  enableTextField(document.ethwan.Ipv6Dns1);
  enableTextField(document.ethwan.Ipv6Dns2);
 }
}
function disableFixedIpInput()
{
 disableTextField(document.ethwan.ip);
 disableTextField(document.ethwan.remoteIp);
 disableTextField(document.ethwan.netmask);
}
function enableFixedIpInput()
{
 enableTextField(document.ethwan.ip);
 enableTextField(document.ethwan.remoteIp);
 if (document.ethwan.adslConnectionMode.value == 4)
  disableTextField(document.ethwan.netmask);
 else
  enableTextField(document.ethwan.netmask);
}
function ipTypeSelection()
{
 if ( document.ethwan.ipMode[0].checked ) {
  enableFixedIpInput();
 } else {
  disableFixedIpInput();
 }
}
function enable_pppObj()
{
 enableTextField(document.ethwan.pppUserName);
 enableTextField(document.ethwan.pppPassword);
 enableTextField(document.ethwan.pppConnectType);
 document.ethwan.gwStr[0].disabled = false;
 document.ethwan.gwStr[1].disabled = false;
 enableTextField(document.ethwan.dstGtwy);
 document.ethwan.wanIf.disabled = false;
 pppTypeSelection();
 autoDGWclicked();
}
function pppSettingsEnable()
{
 document.getElementById('tbl_ppp').style.display='block';
 enable_pppObj();
}
function disable_pppObj()
{
 disableTextField(document.ethwan.pppUserName);
 disableTextField(document.ethwan.pppPassword);
 disableTextField(document.ethwan.pppIdleTime);
 disableTextField(document.ethwan.pppConnectType);
 document.ethwan.gwStr[0].disabled = true;
 document.ethwan.gwStr[1].disabled = true;
 disableTextField(document.ethwan.dstGtwy);
 document.ethwan.wanIf.disabled = true;
}
function pppSettingsDisable()
{
 document.getElementById('tbl_ppp').style.display='none';
 disable_pppObj();
}
function enable_ipObj()
{
 document.ethwan.ipMode[0].disabled = false;
 document.ethwan.ipMode[1].disabled = false;
 document.ethwan.gwStr[0].disabled = false;
 document.ethwan.gwStr[1].disabled = false;
 enableTextField(document.ethwan.dstGtwy);
 document.ethwan.wanIf.disabled = false;
 ipTypeSelection();
 autoDGWclicked();
}
function ipSettingsEnable()
{
 document.getElementById('tbl_ip').style.display='';
 enable_ipObj();
}
function disable_ipObj()
{
 document.ethwan.ipMode[0].disabled = true;
 document.ethwan.ipMode[1].disabled = true;
 document.ethwan.gwStr[0].disabled = true;
 document.ethwan.gwStr[1].disabled = true;
 disableTextField(document.ethwan.dstGtwy);
 document.ethwan.wanIf.disabled = true;
 disableFixedIpInput();
}
function ipSettingsDisable()
{
 document.getElementById('tbl_ip').style.display='none';
 disable_ipObj();
}
function ipModeSelection()
{
 if (document.ethwan.ipUnnum.checked) {
  disable_pppObj();
  disable_ipObj();
  document.ethwan.gwStr[0].disabled = false;
  document.ethwan.gwStr[1].disabled = false;
  enableTextField(document.ethwan.dstGtwy);
  document.ethwan.wanIf.disabled = false;
 }
 else
  enable_ipObj();
}
function adslConnectionModeSelection()
{
 document.ethwan.naptEnabled.disabled = false;
 document.ethwan.igmpEnabled.disabled = false;
 document.ethwan.ipUnnum.disabled = true;
 document.ethwan.droute[0].disabled = false;
 document.ethwan.droute[1].disabled = false;
 document.getElementById('tbl_ppp').style.display='none';
 document.getElementById('tbl_ip').style.display='none';
 if (<% checkWrite("6rdShow"); %>)
  document.getElementById('6rdDiv').style.display='none';
 if (<% checkWrite("IPv6Show"); %>) {
  ipv6SettingsEnable();
  document.getElementById('tbprotocol').style.display='';
  document.ethwan.IpProtocolType.disabled = false;
 }
 e = document.getElementById("qosEnabled");
 if (e) e.disabled = false;
 if ( <% checkWrite("is_rtk_dev_ap"); %> ) document.ethwan.qosEnabled.disabled = false;
 switch(document.ethwan.adslConnectionMode.value){
  case '0':
   document.ethwan.naptEnabled.disabled = true;
   document.ethwan.igmpEnabled.disabled = true;
   document.ethwan.droute[0].disabled = true;
   document.ethwan.droute[1].disabled = true;
   pppSettingsDisable();
   ipSettingsDisable();
   if (<% checkWrite("IPv6Show"); %>) {
    ipv6SettingsDisable();
    document.getElementById('tbprotocol').style.display="none";
   }
   if (e) e.disabled = true;
   if ( <% checkWrite("is_rtk_dev_ap"); %> ) document.ethwan.qosEnabled.disabled = true;
   break;
  case '1':
   pppSettingsDisable();
   ipSettingsEnable();
   break;
  case '2':
   document.getElementById('tbl_ppp').style.display='';
   ipSettingsDisable();
   pppSettingsEnable();
   break;
  case '8':
   if (<% checkWrite("IPv6Show"); %> && <% checkWrite("6rdShow"); %>)
   {
    document.getElementById('6rdDiv').style.display='';
    document.ethwan.droute[0].checked = false;
    document.ethwan.droute[1].checked = true;
    document.ethwan.IpProtocolType.value = 3;
    document.ethwan.AddrMode.value = 8;
    ipSettingsEnable();
    ipv6SettingsDisable();
    document.getElementById('tbprotocol').style.display="none";
   }
   break;
  default:
   pppSettingsDisable();
   ipSettingsEnable();
 }
}
function naptClicked()
{
 if (document.ethwan.adslConnectionMode.selectedIndex == 3) {
  if (document.ethwan.naptEnabled.checked == true) {
   document.ethwan.ipUnnum.checked = false;
   document.ethwan.ipUnnum.disabled = true;
  }
  else
   document.ethwan.ipUnnum.disabled = false;
  ipModeSelection();
 }
}
function hideGWInfo(hide) {
 var status = false;
 if (hide == 1)
  status = true;
 changeBlockState('gwInfo', status);
 if (hide == 0) {
  with (document.forms[0]) {
   if (dgwstatus == 255) {
    if (isValidIpAddress(gtwy) == true) {
     gwStr[0].checked = true;
     gwStr[1].checked = false;
     dstGtwy.value=gtwy;
     wanIf.disabled=true
    } else {
     gwStr[0].checked = false;
     gwStr[1].checked = true;
     dstGtwy.value = '';
    }
   }
   else if (dgwstatus != 239) {
     gwStr[1].checked = true;
     gwStr[0].checked = false;
     wanIf.disabled=false;
     wanIf.value=dgwstatus;
     dstGtwy.disabled=true;
   } else {
     gwStr[1].checked = false;
     gwStr[0].checked = true;
     wanIf.disabled=true;
     dstGtwy.disabled=false;
   }
  }
 }
}
function autoDGWclicked() {
 if (document.ethwan.droute[0].checked == true) {
  hideGWInfo(1);
 } else {
  hideGWInfo(0);
 }
}
function gwStrClick() {
 with (document.forms[0]) {
  if (gwStr[1].checked == true) {
   dstGtwy.disabled = true;
   wanIf.disabled = false;
  }
  else {
   dstGtwy.disabled = false;
   wanIf.disabled = true;
  }
       }
}
function wanAddrModeChange()
{
 document.getElementById('secIPv6Div').style.display="none";
 document.getElementById('dhcp6c_block').style.display="none";
 if (document.ethwan.AddrMode.value == 0)
  document.ethwan.AddrMode.value = 1;
 switch(document.ethwan.AddrMode.value)
 {
  case '1':
   document.ethwan.iana.checked=false;
   document.ethwan.iapd.checked=true;
   break;
  case '2':
   document.getElementById('secIPv6Div').style.display='';
   break;
  case '16':
   document.getElementById('dhcp6c_block').style.display='';
   document.ethwan.iana.checked=true;
   document.ethwan.iapd.checked=true;
   break;
  default:
 }
}
function ipv6WanUpdate()
{
 wanAddrModeChange()
}
function ipv6SettingsDisable()
{
 document.getElementById('tbipv6wan').style.display="none";
 document.getElementById('secIPv6Div').style.display="none";
 document.getElementById('dhcp6c_block').style.display="none";
 document.getElementById('IPv6DnsDiv').style.display="none";
 document.getElementById('DSLiteDiv').style.display="none";
 if (<% checkWrite("MAPEShow"); %>){
  document.getElementById('mape_div').style.display="none";
 }
}
function ipv6SettingsEnable()
{
 if(document.ethwan.IpProtocolType.value != 1){
  document.getElementById('tbipv6wan').style.display='';
  document.getElementById('IPv6DnsDiv').style.display='';
  if (document.ethwan.IpProtocolType.value == 2) {
   document.getElementById('DSLiteDiv').style.display='';
   dsliteSettingChange();
   if (<% checkWrite("MAPEShow"); %>){
    document.getElementById('mape_div').style.display='';
    mapeSettingChange();
   }
  }
  else{
   document.getElementById('DSLiteDiv').style.display="none";
   if (<% checkWrite("MAPEShow"); %>){
    document.getElementById('mape_div').style.display="none";
   }
  }
  ipv6WanUpdate();
   }
}
function dsliteSettingChange()
{
 with ( document.forms[0] )
 {
  if(dslite_enable.checked == true){
   dslite_mode_div.style.display = '';
   dsliteAftrModeChange();
   if(<% checkWrite("MAPEShow"); %>){
    document.getElementById('mape_div').style.display="none";
    document.getElementById('mape_enable').checked = false;
   }
  }
  else{
   dslite_mode_div.style.display = 'none';
   dslite_aftr_hostname_div.style.display = 'none';
   if(<% checkWrite("MAPEShow"); %>){
    document.getElementById('mape_div').style.display="";
   }
  }
 }
}
function dsliteAftrModeChange()
{
 with ( document.forms[0] )
 {
  var dslitemode =dslite_aftr_mode.value;
  dslite_aftr_hostname_div.style.display = 'none';
  switch(dslitemode){
   case '0':
     break;
   case '1':
     dslite_aftr_hostname_div.style.display = '';
     if(dslite_aftr_hostname.value == "::")
      dslite_aftr_hostname.value ="";
     break;
  }
 }
}
function mapeSettingChange()
{
 with ( document.forms[0] )
 {
  if(mape_enable.checked == true){
   mape_mode_div.style.display = '';
   mapeModeChange();
   document.getElementById('DSLiteDiv').style.display="none";
   document.getElementById('dslite_enable').checked = false;
  }
  else{
   mape_mode_div.style.display = 'none';
   mape_static_div.style.display = 'none';
   mape_fmr_tbl_div.style.display = 'none';
   document.getElementById('DSLiteDiv').style.display="";
  }
 }
}
function mapeModeChange()
{
 with ( document.forms[0] )
 {
  var mape_mode_val =mape_mode.value;
  switch(mape_mode_val){
   case '0':
    mape_static_div.style.display = 'none';
    break;
   case '1':
    mape_static_div.style.display = '';
    mape_fmr_tbl_div.style.display = '';
    break;
   default:
    break;
  }
 }
}
function mapeFmrPostEntry(v6Prefix, v6PrefixLen, v4Prefix, v4PrefixLen, eaLen, offset)
{
 document.ethwan.mape_fmrV6Prefix.value = v6Prefix;
 document.ethwan.mape_fmrV6PrefixLen.value= v6PrefixLen;
 document.ethwan.mape_fmrV4Prefix.value = v4Prefix;
 document.ethwan.mape_fmrV4PrefixLen.value = v4PrefixLen;
 document.ethwan.mape_fmrEaLen.value = eaLen;
 document.ethwan.mape_fmrPsidOffset.value = offset;
 mapFmrSelect = 1;
}
function mapeAddFmrClick(obj)
{
 if(document.ethwan.mape_fmrV6Prefix.value == ""){
  alert('Please input the IPv6 prefix for fmr!');
  return false;
 }
 if(document.ethwan.mape_fmrV6PrefixLen.value == ""){
  alert('Please input the IPv6 prefix length for fmr!');
  return false;
 }
 if(document.ethwan.mape_fmrV4Prefix.value == ""){
  alert('Please input the IPv4 prefix for fmr!');
  return false;
 }
 if(document.ethwan.mape_fmrV4PrefixLen.value == ""){
  alert('Please input the IPv4 prefix length for fmr!');
  return false;
 }
 if(document.ethwan.mape_fmrEaLen.value == ""){
  alert('Please input the EA length for fmr!');
  return false;
 }
 if(document.ethwan.mape_fmrPsidOffset.value == ""){
  alert('Please input the psid offset for fmr!');
  return false;
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function mapeModifyFmrClick(obj){
 if (!mapFmrSelect) {
  alert('Please select an FMR entry to modify!');
  return false;
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return addClick();
}
function mapeRemoveFmrClick(obj){
 if (!mapFmrSelect) {
  alert('Please select an FMR entry to delect!');
  return false;
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function protocolChange()
{
 ipver = document.ethwan.IpProtocolType.value;
 if(document.ethwan.IpProtocolType.value == 1){
  if( document.ethwan.adslConnectionMode.selectedIndex ==1 ||
   document.ethwan.adslConnectionMode.selectedIndex ==4 ||
   document.ethwan.adslConnectionMode.selectedIndex ==5)
   ipSettingsEnable();
   ipv6SettingsDisable();
 }else{
  if(document.ethwan.IpProtocolType.value == 2){
   ipSettingsDisable();
  }else{
   if( document.ethwan.adslConnectionMode.selectedIndex ==1 ||
    document.ethwan.adslConnectionMode.selectedIndex ==4 ||
    document.ethwan.adslConnectionMode.selectedIndex ==5)
    ipSettingsEnable();
  }
  if(document.ethwan.adslConnectionMode.value != '8')
  {
   ipv6SettingsEnable();
  }
 }
}
</script>
</head>
<BODY>
<div class="intro_main ">
 <p class="intro_title"><% multilang("12" "LANG_ETHERNET_WAN"); %></p>
 <p class="intro_content"> <% multilang("289" "LANG_PAGE_DESC_CONFIGURE_PARAMETERS"); %><% multilang("12" "LANG_ETHERNET_WAN"); %></p>
</div>
<form action=/boaform/admin/formWanEth method=POST name="ethwan">
<!--<table border="0" cellspacing="4" width="800" <% WANConditions(); %>>
 <tr>
  <td>
   <b><% multilang("290" "LANG_WAN_MODE"); %>:</b>
   <input type="checkbox" value=1 name="wmchkbox">ADSL
   <input type="checkbox" value=2 name="wmchkbox">Ethernet&nbsp;&nbsp;&nbsp;&nbsp;
   <input type="hidden" name="wan_mode" value=0>
   <input type="submit" value="Submit" name="submitwan" onClick="return SubmitWANMode()">
  </td>
 </tr>
 <tr><td><hr size=1 noshade align=top></td></tr>
</table> -->
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <% ShowChannelMode("ethcmode"); %>
  </tr>
  <tr>
   <% ShowNAPTSetting(); %>
  </tr>
  <tr>
   <% ShowIGMPSetting(); %>
  </tr>
  <tr>
   <th <% checkWrite("IPQoS"); %>>
    <% multilang("333" "LANG_ENABLE_QOS"); %>: </th>
   <td><input type="checkbox" name="qosEnabled" size="2" maxlength="2" value="ON" >
   </th>
  </tr>
  <tr>
   <th><% multilang("297" "LANG_DEFAULT_ROUTE"); %>:</th>
   <td><input type=radio value=0 name="droute"><% multilang("254" "LANG_DISABLE"); %>
    <input type=radio value=1 name="droute" checked><% multilang("255" "LANG_ENABLE"); %>
   </td>
  </tr>
  <% ShowIpProtocolType(); %>
 </table>
</div>
<% ShowPPPIPSettings("pppoeStatus"); %>
<% ShowDefaultGateway("p2p"); %>
<% Show6rdSetting(); %>
<% ShowIPV6Settings(); %>
<div class="btn_ctl">
 <input type="hidden" value="/waneth.asp" name="submit-url">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="apply" onClick="return applyCheck(this)">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 initConnectMode = document.ethwan.adslConnectionMode.selectedIndex;
 <% initPage("ethwan"); %>
 <% checkWrite("ethwanSelection"); %>
 <% GetDefaultGateway(); %>
 adslConnectionModeSelection();
 var RTKIPv6Enable= <% checkWrite("rtk_ipv6_enable"); %>;
 if(RTKIPv6Enable == "yes")
 {
  protocolChange();
  dnsModeV6Clicked();
 }
 dnsModeClicked();
 <% checkWrite("devType"); %>
</script>
</form>
</body>
</html>
