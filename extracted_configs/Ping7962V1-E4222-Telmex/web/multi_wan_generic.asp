<%SendWebHeadStr(); %>
<title><% getWanIfDisplay(); %> <% multilang("11" "LANG_WAN"); %></title>
<script type="text/javascript" src="base64_code.js"></script>
<script language="javascript">
var initConnectMode;
var pppConnectStatus=0;
var dgwstatus;
var gtwy;
var interfaceInfo = '';
var gtwyIfc ='';
var gwInterface=0;
var ipver=1;
var curlink = null;
var ctype = 4;
var temp_user_mvid_value = 0;
var cgi = new Object();
var links = new Array();
with(links){<% initPageWaneth(); %>}
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
   alert('<% multilang("2019" "LANG_A_DEFAULT_GATEWAY_HAS_TO_BE_SELECTED"); %>');
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
function check_dhcp_opts()
{
 with (document.forms[0])
 {
  if(typeof enable_opt_77 !== 'undefined' &&enable_opt_77.checked)
  {
   if (opt77_val.value=="") {
    alert('<% multilang("1126" "LANG_USER_CLASS_CANNOT_BE_EMPTY"); %>');
    opt77_val.focus();
    return false;
   }
   if (checkString(opt77_val.value) == 0) {
    alert('<% multilang("1127" "LANG_INVALID_USER_CLASS"); %>');
    opt77_val.focus();
    return false;
   }
  }
  if(typeof enable_opt_60 !== 'undefined' &&enable_opt_60.checked)
  {
   if (opt60_val.value=="") {
    alert('<% multilang("2020" "LANG_VENDOR_ID_CANNOT_BE_EMPTY"); %>');
    opt60_val.focus();
    return false;
   }
   if (checkString(opt60_val.value) == 0) {
    alert('<% multilang("2021" "LANG_INVALID_VENDOR_ID"); %>');
    opt60_val.focus();
    return false;
   }
  }
  if(typeof enable_opt_61 !== 'undefined'&&enable_opt_61.checked)
  {
   if (iaid.value=="") {
    alert('<% multilang("2022" "LANG_IAID_CANNOT_BE_EMPTY"); %>');
    iaid.focus();
    return false;
   }
   if (checkDigit(iaid.value) == 0) {
    alert('<% multilang("2023" "LANG_IAID_SHOULD_BE_A_NUMBER"); %>');
    iaid.focus();
    return false;
   }
   if(duid_type[1].checked)
   {
    if (duid_ent_num.value=="") {
     alert('<% multilang("2024" "LANG_ENTERPRISE_NUMBER_CANNOT_BE_EMPTY"); %>');
     duid_ent_num.focus();
     return false;
    }
    if (checkDigit(duid_ent_num.value) == 0) {
     alert('<% multilang("2025" "LANG_ENTERPRISE_NUMBER_SHOULD_BE_A_NUMBER"); %>');
     duid_ent_num.focus();
     return false;
    }
    if (duid_id.value=="") {
     alert('<% multilang("2026" "LANG_DUID_IDENTIFIER_CANNOT_BE_EMPTY"); %>');
     duid_id.focus();
     return false;
    }
    if (checkString(duid_id.value) == 0) {
     alert('<% multilang("2027" "LANG_INVALID_DUID_IDENTIFIER"); %>');
     duid_id.focus();
     return false;
    }
   }
  }
  if(typeof enable_opt_125 !== 'undefined' &&enable_opt_125.checked)
  {
   if (manufacturer.value=="") {
    alert('<% multilang("2028" "LANG_MANUFACTURER_OUI_CANNOT_BE_EMPTY"); %>');
    manufacturer.focus();
    return false;
   }
   if (checkString(manufacturer.value) == 0) {
    alert('<% multilang("2029" "LANG_INVALID_MANUFACTURER_OUI"); %>');
    manufacturer.focus();
    return false;
   }
   if (product_class.value=="") {
    alert('<% multilang("2030" "LANG_PRODUCT_CLASS_CANNOT_BE_EMPTY"); %>');
    product_class.focus();
    return false;
   }
   if (checkString(product_class.value) == 0) {
    alert('<% multilang("2031" "LANG_INVALID_PRODUCT_CLASS"); %>');
    product_class.focus();
    return false;
   }
   if (model_name.value=="") {
    alert('<% multilang("2032" "LANG_MODEL_NAME_CANNOT_BE_EMPTY"); %>');
    model_name.focus();
    return false;
   }
   if (checkString(model_name.value) == 0) {
    alert('<% multilang("2033" "LANG_INVALID_MODEL_NAME"); %>');
    model_name.focus();
    return false;
   }
   if (serial_num.value=="") {
    alert('<% multilang("2034" "LANG_SERIAL_NUMBER_CANNOT_BE_EMPTY"); %>');
    serial_num.focus();
    return false;
   }
   if (checkString(serial_num.value) == 0) {
    alert('<% multilang("2034" "LANG_SERIAL_NUMBER_CANNOT_BE_EMPTY"); %>');
    serial_num.focus();
    return false;
   }
  }
 }
}
function isAllStar(str)
{
  for (var i=0; i<str.length; i++) {
   if ( str.charAt(i) != '*' ) {
   return false;
 }
  }
  return true;
}
function disableUsernamePassword()
{
 disableTextField(document.ethwan.pppUserName);
 if(!isAllStar(document.ethwan.pppPassword.value))
  disableTextField(document.ethwan.pppPassword);
}
function applyCheck(obj)
{
 var tmplst = "";
 var ptmap = 0;
 var pmchkpt = document.getElementById("tbl_pmap");
 if (pmchkpt) {
  with (document.forms[0]) {
   for (var i = 0; i < 14; i++) {
    if (!chkpt[i])
     break;
    if (chkpt[i].checked == true)
     ptmap |= (0x1 << i);
   }
   itfGroup.value = ptmap;
  }
 }
 if (checkDefaultGW()==false)
  return false;
 if (document.ethwan.vlan.checked == true) {
  if (document.ethwan.vid.value == "") {
   alert('<% multilang("2036" "LANG_VID_SHOULD_NOT_BE_EMPTY"); %>');
   document.ethwan.vid.focus();
   return false;
  }
  else if(document.ethwan.vid.value<0 ||document.ethwan.vid.value>4095) {
    alert("<% multilang("2320" "LANG_INCORRECT_VLAN_ID_SHOULE_BE_1_4095"); %>");
    return false;
  }
 }
 if (document.ethwan.multicast_vid.style.display != "none")
 {
  var multicast_vid_value = document.ethwan.multicast_vid.value
  if (multicast_vid_value.length != 0)
  {
   var multicast_vid_value = document.ethwan.multicast_vid.value
   if (multicast_vid_value < 1 || multicast_vid_value > 4095)
   {
    alert('<% multilang("2753" "LANG_MCAST_INVALID_VLAN_ID"); %>');
    return false;
   }
  }
 }
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
  document.ethwan.encodePppUserName.value=encode64(document.ethwan.pppUserName.value);
  if (document.ethwan.pppPassword.value=="") {
   alert('<% multilang("2040" "LANG_PPP_PASSWORD_CANNOT_BE_EMPTY"); %>');
   document.ethwan.pppPassword.focus();
   return false;
  }
  if(!isAllStar(document.ethwan.pppPassword.value)){
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
   document.ethwan.encodePppPassword.value=encode64(document.ethwan.pppPassword.value);
  }
  if (document.ethwan.pppConnectType.selectedIndex == 1) {
   if (document.ethwan.pppIdleTime.value <= 0) {
    alert('<% multilang("2043" "LANG_INVALID_PPP_IDLE_TIME"); %>');
    document.ethwan.pppIdleTime.focus();
    return false;
   }
  }
 }
 if (document.ethwan.dns1.value !="")
 {
  if (!checkHostIP(document.ethwan.dns1, 1))
  {
   document.ethwan.dns1.focus();
   return false;
  }
 }
 if (document.ethwan.dns2.value !="")
 {
  if (!checkHostIP(document.ethwan.dns2, 1))
  {
   document.ethwan.dns2.focus();
   return false;
  }
 }
 if (<% checkWrite("IPv6Show"); %>) {
  if(document.ethwan.IpProtocolType.value & 1){
   if ( document.ethwan.adslConnectionMode.value == 1 ) {
    if (document.ethwan.ipMode[0].checked)
    {
     if ( document.ethwan.ipUnnum.disabled || ( !document.ethwan.ipUnnum.disabled && !document.ethwan.ipUnnum.checked )) {
      if (!checkHostIP(document.ethwan.ip, 1))
       return false;
      if (document.ethwan.remoteIp.visiblity == "hidden") {
       if (!checkHostIP(document.ethwan.remoteIp, 1))
       return false;
      }
      if (document.ethwan.adslConnectionMode.value == 1 && !checkNetmask(document.ethwan.netmask, 1))
       return false;
     }
    }
    else
    {
     if(check_dhcp_opts() == false)
      return false;
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
 if(document.ethwan.lkname.value != "new") tmplst = curlink.name;
 document.ethwan.lst.value = tmplst;
 disableUsernamePassword();
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function deleteCheck(obj)
{
 var tmplst = "";
 if ( document.ethwan.lkname.value == "new" )
 {
  alert('<% multilang("2059" "LANG_NO_LINK_SELECTED"); %>');
  return false;
 }
 tmplst = curlink.name;
 document.ethwan.lst.value = tmplst;
 disableUsernamePassword();
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
 document.ethwan.dnsMode[0].disabled = false;
 document.ethwan.dnsMode[1].disabled = false;
 dnsModeClicked();
}
function enableFixedIpInput()
{
 enableTextField(document.ethwan.ip);
 enableTextField(document.ethwan.remoteIp);
 if (document.ethwan.adslConnectionMode.value == 4)
  disableTextField(document.ethwan.netmask);
 else
  enableTextField(document.ethwan.netmask);
 document.ethwan.dnsMode[0].disabled = false;
 document.ethwan.dnsMode[1].disabled = false;
 dnsModeClicked();
}
function disableDNSv6Input()
{
 document.ethwan.dnsV6Mode[0].disabled = false;
 document.ethwan.dnsV6Mode[1].disabled = false;
 dnsModeV6Clicked();
}
function enableDNSv6Input()
{
 document.ethwan.dnsV6Mode[0].disabled = true;
 document.ethwan.dnsV6Mode[1].disabled = true;
 dnsModeV6Clicked();
}
function ipTypeSelection(init)
{
 if ( document.ethwan.ipMode[0].checked ) {
  enableFixedIpInput();
  showDhcpOptSettings(0);
 } else {
  disableFixedIpInput();
  showDhcpOptSettings(1);
 }
 if (init == 0)
 {
  if ( document.ethwan.ipMode[0].checked )
   document.ethwan.dnsMode[1].checked = true;
  else
   document.ethwan.dnsMode[0].checked = true;
  dnsModeClicked();
 }
 pppSettingsDisable();
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
 ipTypeSelection(1);
 autoDGWclicked();
}
function ipSettingsEnable()
{
 document.getElementById('tbl_ip').style.display='block';
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
 showDhcpOptSettings(0);
 disable_ipObj();
}
function showDuidType2(show)
{
 if(show == 1)
 {
  document.getElementById('duid_t2_ent').style.display = 'block';
  document.getElementById('duid_t2_id').style.display = 'block';
 }
 else
 {
  document.getElementById('duid_t2_ent').style.display = 'none';
  document.getElementById('duid_t2_id').style.display = 'none';
 }
}
function showDhcpOptSettings(show)
{
 var dhcp_opt = document.getElementById('tbl_dhcp_opt');
 if(dhcp_opt == null)
  return ;
 if(show == 1)
 {
  document.getElementById('tbl_dhcp_opt').style.display='block';
 }
 else
  document.getElementById('tbl_dhcp_opt').style.display='none';
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
 else{
  enable_ipObj();
  pppSettingsDisable();
 }
}
function updateBrMode(isLinkChanged)
{
 var brmode_ops = document.getElementById('brmode');
 if(!brmode_ops)
  return ;
 if(!isLinkChanged)
 {
  document.ethwan.br.checked = false;
  brmode_ops.value = 0;
  brmode_ops.disabled = true;
 }
 if(document.ethwan.adslConnectionMode.value == 0)
 {
  document.getElementById('br_row').style.display = "none";
  brmode_ops.disabled = false;
  var options = document.forms['ethwan']['ctype'].options;
  for (var i=0, iLen=options.length; i<iLen; i++) {
   if (i!==0 && i!==1){
    options[i].disabled = true;
   }
  }
 }
 else
 {
  document.getElementById('br_row').style.display = "";
  var options = document.forms['ethwan']['ctype'].options;
                for (var i=0, iLen=options.length; i<iLen; i++) {
                        if (i!==0 && i!==1){
                                options[i].disabled = false;
                        }
                }
 }
}
function brClicked()
{
 var brmode_ops = document.getElementById('brmode');
 if(!brmode_ops)
  return ;
 if(document.ethwan.br.checked)
  brmode_ops.disabled = false;
 else
  brmode_ops.disabled = true;
}
function dynamic_create_ipv6_addrmode_options(addr_mode)
{
 var addrmode_options_len = document.getElementById("AddrMode").length;
 var ipv6_auto_enable = <% checkWrite("ConfigIPv6_wan_auto_detect"); %>;
 if (ipv6_auto_enable == 1)
 {
  if (addr_mode == 1 || addr_mode == 2)
  {
   var get_ipv6_auto_option = 0;
   for(var i = 0; i < addrmode_options_len; i++)
   {
    if (document.getElementById("AddrMode").options[i].value == "32")
    {
     get_ipv6_auto_option = 1;
    }
   }
   if (get_ipv6_auto_option != 1)
   {
    var ipv6_auto_mode_option_name = "<% checkWrite("IPv6_auto_mode_string"); %>";
    document.getElementById("AddrMode").options[addrmode_options_len] = new Option(ipv6_auto_mode_option_name, 32);
   }
  }
  else if (addr_mode == 3)
  {
   for(var i = 0; i < addrmode_options_len; i++)
   {
    if (document.getElementById("AddrMode").options[i].value == "32")
    {
     document.getElementById("AddrMode").remove(i);
    }
   }
  }
 }
}
function adslConnectionModeSelection(isLinkChanged)
{
 document.ethwan.naptEnabled.disabled = false;
 document.ethwan.igmpEnabled.disabled = false;
 document.ethwan.mldEnabled.disabled = false;
 document.ethwan.ipUnnum.disabled = true;
 document.ethwan.droute[0].disabled = false;
 document.ethwan.droute[1].disabled = false;
 if(!isLinkChanged)
  document.ethwan.mtu.value = 1500;
 document.getElementById('tbl_ppp').style.display = 'none';
 document.getElementById('tbl_ip').style.display = 'none';
 if (document.getElementById('tbl_dhcp_opt') != null)
  document.getElementById('tbl_dhcp_opt').style.display = 'none';
 if (<% checkWrite("6rdShow"); %>)
  document.getElementById('6rdDiv').style.display ='none';
 if (<% checkWrite("IPv6Show"); %>) {
  ipv6SettingsEnable();
  document.getElementById('tbprotocol').style.display = "";
  document.ethwan.IpProtocolType.disabled = false;
 }
 else if (<% checkWrite("ConfigIPv6"); %>)
  document.getElementById('tbprotocol').style.display = "none";
 if (<% checkWrite("is_rtk_dev_ap"); %>)
  document.ethwan.qosEnabled.disabled = false;
 switch (document.ethwan.adslConnectionMode.value) {
  case '0':
   if (<% checkWrite("ConfigIPv6"); %>)
   document.getElementById('tbprotocol').style.display = "none";
   document.getElementById('tbmtu').style.display = 'none';
   document.ethwan.naptEnabled.disabled = true;
   document.ethwan.igmpEnabled.disabled = true;
   document.ethwan.mldEnabled.disabled = true;
   document.ethwan.droute[0].disabled = true;
   document.ethwan.droute[1].disabled = true;
   pppSettingsDisable();
   ipSettingsDisable();
   if (<% checkWrite("IPv6Show"); %>) {
    ipv6SettingsDisable();
    document.getElementById('tbprotocol').style.display = "none";
   }
   if ( <% checkWrite("is_rtk_dev_ap"); %> ) document.ethwan.qosEnabled.disabled = true;
   break;
  case '8':
   if (<% checkWrite("IPv6Show"); %> && <% checkWrite("6rdShow"); %>)
   {
    document.getElementById('tbmtu').style.display = 'table-row';
    document.getElementById('6rdDiv').style.display = 'block';
    document.ethwan.droute[0].checked = false;
    document.ethwan.droute[1].checked = true;
    document.ethwan.IpProtocolType.value = 3;
    document.ethwan.AddrMode.value = 8;
    ipSettingsEnable();
    ipv6SettingsDisable();
    document.getElementById('tbprotocol').style.display = "none";
   }
   break;
  case '1':
   dynamic_create_ipv6_addrmode_options(1);
   document.getElementById('tbmtu').style.display = 'table-row';
   pppSettingsDisable();
   if (<% checkWrite("IPv6Show"); %>) {
    if(document.ethwan.IpProtocolType.value != 2)
     ipSettingsEnable();
   }
   else
    ipSettingsEnable();
   if(!isLinkChanged)
    document.ethwan.naptEnabled.checked = true;
   break;
  case '2':
   dynamic_create_ipv6_addrmode_options(1);
   if(!isLinkChanged)
    document.ethwan.mtu.value = 1492;
   document.getElementById('tbmtu').style.display = 'table-row';
   document.getElementById('tbl_ppp').style.display = 'block';
   ipSettingsDisable();
   pppSettingsEnable();
   if(!isLinkChanged)
    document.ethwan.naptEnabled.checked = true;
   break;
  case '3':
   dynamic_create_ipv6_addrmode_options(3);
   break;
  default:
   pppSettingsDisable();
   ipSettingsEnable();
 }
 updateBrMode(isLinkChanged);
}
function naptClicked()
{
 if (document.ethwan.adslConnectionMode.value == 3) {
  if (document.ethwan.naptEnabled.checked == true) {
   document.ethwan.ipUnnum.checked = false;
   document.ethwan.ipUnnum.disabled = true;
  }
  else
   document.ethwan.ipUnnum.disabled = false;
  ipModeSelection();
 }
}
function vlanClicked()
{
 if (document.ethwan.vlan.checked)
 {
  document.ethwan.vid.disabled = false;
  document.ethwan.vprio.disabled = false;
 }
 else {
  document.ethwan.vid.disabled = true;
  document.ethwan.vprio.disabled = true;
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
   document.getElementById('secIPv6Div').style.display='block';
   break;
  case '16':
   document.getElementById('dhcp6c_block').style.display='block';
   document.ethwan.iana.checked=true;
   document.ethwan.iapd.checked=true;
   break;
  case '32':
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
}
function ipv6SettingsEnable()
{
 if(document.ethwan.IpProtocolType.value != 1){
  document.getElementById('tbipv6wan').style.display="block";
  document.getElementById('IPv6DnsDiv').style.display="block";
  if (document.ethwan.IpProtocolType.value == 2) {
   document.getElementById('DSLiteDiv').style.display="block";
   dsliteSettingChange();
  }
  else
   document.getElementById('DSLiteDiv').style.display="none";
  ipv6WanUpdate();
   }
}
function dsliteSettingChange()
{
 with ( document.forms[0] )
 {
  if(dslite_enable.checked == true){
   if (adslConnectionMode.value == 2) {
    if(mtu.value > 1400)
     mtu.value = 1400;
   }
   else {
    if(mtu.value > 1400)
     mtu.value = 1400;
   }
   dslite_mode_div.style.display = 'block';
   dsliteAftrModeChange();
  }
  else{
   if (adslConnectionMode.value == 2) {
    mtu.value = 1492;
   }
   else {
    mtu.value = 1500;
   }
   dslite_mode_div.style.display = 'none';
   dslite_aftr_hostname_div.style.display = 'none';
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
     dslite_aftr_hostname_div.style.display = 'block';
     if(dslite_aftr_hostname.value == "::")
      dslite_aftr_hostname.value ="";
     break;
  }
 }
}
function protocolChange()
{
 ipver = document.ethwan.IpProtocolType.value;
 if(document.ethwan.IpProtocolType.value == 1){
  if( document.ethwan.adslConnectionMode.value ==1 ||
   document.ethwan.adslConnectionMode.value ==4 ||
   document.ethwan.adslConnectionMode.value ==5){
    document.getElementById("igmpenable").style.display = "table-row";
    ipSettingsEnable();
   }
   document.getElementById("mldenable").style.display = "none";
   ipv6SettingsDisable();
 }else{
  if(document.ethwan.IpProtocolType.value == 2){
   document.getElementById("igmpenable").style.display = "none";
   ipSettingsDisable();
  }else{
   if( document.ethwan.adslConnectionMode.value ==1 ||
    document.ethwan.adslConnectionMode.value ==4 ||
    document.ethwan.adslConnectionMode.value ==5){
     document.getElementById("igmpenable").style.display = "table-row";
     ipSettingsEnable();
   }
  }
  document.getElementById("mldenable").style.display = "table-row";
  ipv6SettingsEnable();
 }
}
function on_linkchange(itlk)
{
 var pmchkpt = document.getElementById("tbl_pmap");
 temp_user_mvid_value = 0;
 with ( document.forms[0] )
 {
  if(itlk == null)
  {
   mtu.value=1500;
   adslConnectionMode.value = pppConnectType.value = 0;
   if(typeof brmode != "undefined")
    brmode.value = 0;
   if(<% checkWrite("ConfigIPv6"); %>)
   IpProtocolType.value = 1;
   if (<% checkWrite("IPv6Show"); %>)
   AddrMode.value = 1;
   ctype.value = 4;
   ipMode[0].checked = droute[0].checked = dnsMode[1].checked = dnsV6Mode[1].checked =true;
   chEnable[0].checked = true;
   if(typeof duid_type !== 'undefined')
    duid_type[1].checked = true;
   naptEnabled.checked = vlan.checked = qosEnabled.checked = igmpEnabled.checked = mldEnabled.checked = false;
   if(typeof enable_opt_77 !== 'undefined')
    enable_opt_77.checked = false;
   if(typeof enable_opt_60 !== 'undefined')
    enable_opt_60.checked = enable_opt_61.checked = enable_opt_125.checked = false;
   vprio.value = vid.value = "0";
   vid.value = "";
   multicast_vid.value = "";
   ip.value = remoteIp.value = "0.0.0.0";
   netmask.value = "255.255.255.0";
   pppUserName.value = pppPassword.value = acName.value = serviceName.value = dns1.value = dns2.value = "";
   auth.value = 0;
   Ipv6Addr.value = "";
   Ipv6PrefixLen.value = "";
   Ipv6Gateway.value = "";
   dnsV6Mode[0].checked = true;
   disableDNSv6Input();
   iana.checked = true;
   iapd.checked = false;
   if(typeof document.ethwan.br != "undefined")
    document.ethwan.br.checked = false;
   if (pmchkpt)
    for (var i = 0; i < 14; i++) {
     if (!chkpt[i])
      break;
     chkpt[i].checked = false;
    }
  }
  else
  {
   mtu.value=itlk.mtu;
   adslConnectionMode.value = itlk.cmode;
   if (<% checkWrite("IPv6Show"); %>)
   AddrMode.value = itlk.AddrMode;
   ctype.value = itlk.applicationtype;
   if(document.ethwan.br)
   {
    document.ethwan.br.checked = false;
    if(itlk.brmode == 2)
    {
     brmode.value = 0;
     brmode.disabled = true;
    }
    else
    {
     if(itlk.cmode != 0)
      document.ethwan.br.checked = true;
     brmode.value = itlk.brmode;
     brmode.disabled = false;
    }
   }
   if (itlk.napt == 1)
    naptEnabled.checked = true;
   else
    naptEnabled.checked = false;
   if (itlk.enableIGMP == 1)
    igmpEnabled.checked = true;
   else
    igmpEnabled.checked = false;
   if (itlk.enableMLD == 1)
    mldEnabled.checked = true;
   else
    mldEnabled.checked = false;
   if (itlk.enableIpQos == 1)
    qosEnabled.checked = true;
   else
    qosEnabled.checked = false;
   mtu.value = itlk.mtu;
   if (itlk.vlan == 1)
   {
    vlan.checked = true;
    vid.value = itlk.vid;
    vprio.value = itlk.vprio;
   }
   else
   {
    vlan.checked = false;
    <% checkWrite("show_vlan_id"); %>
   }
   if (itlk.applicationtype == 1 || itlk.applicationtype == 8 || itlk.applicationtype == 9){
    document.getElementById("multicast_vid_tr").style.display = "none";
   }
   else
   {
    document.getElementById("multicast_vid_tr").style.display = "table-row";
    if (itlk.mVid == 0)
     multicast_vid.value = "";
    else
     multicast_vid.value = itlk.mVid;
   }
   if (itlk.dgw == 1)
    droute[1].checked = true;
   else
    droute[0].checked = true;
   if (itlk.enable == 1)
    chEnable[0].checked = true;
   else
    chEnable[1].checked = true;
   if(itlk.cmode != 0)
   {
    if(<% checkWrite("ConfigIPv6"); %>)
    {
    IpProtocolType.value = itlk.IpProtocol;
    if (IpProtocolType.value != 1)
    {
     if (itlk.AddrMode & 2)
     {
      Ipv6Addr.value = itlk.Ipv6Addr;
      Ipv6PrefixLen.value = itlk.Ipv6AddrPrefixLen;
      Ipv6Gateway.value = itlk.RemoteIpv6Addr;
     }
     else
     {
      Ipv6Addr.value = "";
      Ipv6PrefixLen.value = "";
      Ipv6Gateway.value = "";
     }
     if (itlk.dnsv6Mode == 1)
     {
      dnsV6Mode[0].checked = true;
      disableDNSv6Input();
     }
     else
     {
      dnsV6Mode[1].checked = true;
      dnsModeV6Clicked();
     }
     Ipv6Dns1.value = itlk.Ipv6Dns1;
     Ipv6Dns2.value = itlk.Ipv6Dns2;
     if (itlk.Ipv6Dhcp)
     {
      if (itlk.Ipv6DhcpRequest & 1)
       iana.checked = true;
      else
       iana.checked = false;
      if (itlk.Ipv6DhcpRequest & 2)
       iapd.checked = true;
      else
       iapd.checked = false;
     }
     if (IpProtocolType.value == 2) {
      dslite_enable.checked = itlk.dslite_enable;
      dslite_aftr_mode.value = itlk.dslite_aftr_mode;
      dslite_aftr_hostname.value = itlk.dslite_aftr_hostname;
     }
     if (itlk.AddrMode & 8)
     {
      adslConnectionMode.value = 8;
      SixrdBRv4IP.value = itlk.SixrdBRv4IP;
      SixrdIPv4MaskLen.value = itlk.SixrdIPv4MaskLen;
      SixrdPrefix.value = itlk.SixrdPrefix;
      SixrdPrefixLen.value = itlk.SixrdPrefixLen;
      ip.value = itlk.ipAddr;
      remoteIp.value = itlk.remoteIpAddr;
      netmask.value = itlk.netMask;
     }
    }else{
     Ipv6Addr.value = "";
     Ipv6PrefixLen.value = "";
     Ipv6Gateway.value = "";
     dnsV6Mode[0].checked = true;
     disableDNSv6Input();
     iana.checked = true;
     iapd.checked = false;
    }
    }
    if (itlk.cmode == 1 || itlk.cmode == 8)
    {
     if (itlk.ipDhcp == 1)
     {
      ipMode[0].checked = false;
      ipMode[1].checked = true;
      ip.value = "";
      remoteIp.value = "";
      netmask.value = "";
     }
     else
     {
      ipMode[0].checked = true;
      ipMode[1].checked = false;
      ip.value = itlk.ipAddr;
      remoteIp.value = itlk.remoteIpAddr;
      netmask.value = itlk.netMask;
     }
     if (itlk.dnsMode == 1)
       dnsMode[0].checked = true;
      else
       dnsMode[1].checked = true;
     dns1.value = itlk.v4dns1;
     dns2.value = itlk.v4dns2;
    }
    else if (itlk.cmode == 2)
    {
     pppUserName.value = decode64(itlk.pppUsername);
     pppPassword.value = itlk.pppPassword;
     pppConnectType.value = itlk.pppCtype;
     pppIdleTime.value = itlk.pppIdleTime;
     auth.value = itlk.pppAuth;
     acName.value = itlk.pppACName;
     serviceName.value = itlk.pppServiceName;
    }
    if(<% checkWrite("ConfigIPv6"); %>)
    protocolChange();
   }
   if(typeof enable_opt_77 !== 'undefined')
   {
    if(itlk.enable_opt_77)
     enable_opt_77.checked = true;
    opt77_val.value = itlk.opt77_val;
   }
   if(typeof enable_opt_60 !== 'undefined')
   {
    if(itlk.enable_opt_60)
     enable_opt_60.checked = true;
    opt60_val.value = itlk.opt60_val;
    if(itlk.enable_opt_61)
     enable_opt_61.checked = true;
    iaid.value = itlk.iaid;
    if(itlk.duid_type == 0)
     duid_type[0].checked = true;
    else
     duid_type[itlk.duid_type - 1].checked = true;
    duid_ent_num.value = itlk.duid_ent_num;
    duid_id.value = itlk.duid_id;
    if(itlk.enable_opt_125)
     enable_opt_125.checked = true;
    manufacturer.value = itlk.manufacturer;
    product_class.value = itlk.product_class;
    model_name.value = itlk.model_name;
    serial_num.value = itlk.serial_num;
   }
   if (pmchkpt)
    for (var i = 0; i < 14; i++) {
     if (!chkpt[i])
      break;
     chkpt[i].checked = (itlk.itfGroup & (0x1 << i));
    }
  }
 }
 if(<% checkWrite("ConfigIPv6"); %>)
 ipver = document.ethwan.IpProtocolType.value;
 vlanClicked();
 autoDGWclicked();
 adslConnectionModeSelection(true);
}
function on_ctrlupdate()
{
 with ( document.forms[0] )
 {
  if(lkname.value == "new")
  {
   curlink = null;
   on_linkchange(curlink);
  }
  else
  {
   curlink = links[lkname.value];
   on_linkchange(curlink);
  }
 }
}
function wan_service_change()
{
 var ctype_value = document.ethwan.ctype.value;
 temp_user_mvid_value = document.getElementById("multicast_vid").value;
 if (ctype_value == 1 || ctype_value == 8 || ctype_value == 9)
 {
  document.getElementById("multicast_vid_tr").style.display = "none";
 }
 else
 {
  document.getElementById("multicast_vid_tr").style.display = "table-row";
  if (curlink.mVid == 0 || temp_user_mvid_value != 0)
  {
   document.getElementById("multicast_vid").value = temp_user_mvid_value;
  }
  else
   document.getElementById("multicast_vid").value = curlink.mVid;
 }
}
function on_init()
{
 sji_docinit(document, cgi);
 with ( document.forms[0] )
 {
  for(var k in links)
  {
   var lk = links[k];
   lkname.options.add(new Option(lk.name, k));
  }
  lkname.options.add(new Option("new link", "new"));
  if(links.length > 0) lkname.selectedIndex = 0;
  on_ctrlupdate();
  protocolChange();
 }
}
function show_Password()
{
 var x = document.getElementById("PPP_Password");
 if (x.type === "password")
 {
  x.type = "text";
 }
 else
 {
  x.type = "password";
 }
}
function show_service_NAME()
{
 var x = document.getElementById("service_NAME");
 if (x.type === "password")
 {
  x.type = "text";
 }
 else
 {
  x.type = "password";
 }
}
</script>
</head>
<BODY onLoad="on_init();">
<div class="intro_main ">
 <p class="intro_title"><% getWanIfDisplay(); %> <% multilang("11" "LANG_WAN"); %></p>
 <p class="intro_content"> <% multilang("289" "LANG_PAGE_DESC_CONFIGURE_PARAMETERS"); %><% getWanIfDisplay(); %><% multilang("11" "LANG_WAN"); %></p>
</div>
<form action=/boaform/admin/formWanEth method=POST name="ethwan">
<!--<table border="0" cellspacing="4" width="800" <% WANConditions(); %>>
 <tr>
  <td>
   <b><% multilang("290" "LANG_WAN_MODE"); %>:</b>
   <span <% checkWrite("wan_mode_atm"); %>><input type="checkbox" value=1 name="wmchkbox">ATM</span>
   <span <% checkWrite("wan_mode_ethernet"); %>><input type="checkbox" value=2 name="wmchkbox">Ethernet</span>
   <span <% checkWrite("wan_mode_ptm"); %>><input type="checkbox" value=4 name="wmchkbox">PTM</span>
   <span <% checkWrite("wan_mode_bonding"); %>><input type="checkbox" value=8 name="wmchkbox">Bonding</span>&nbsp;&nbsp;&nbsp;&nbsp;
   <input type="hidden" name="wan_mode" value=0>
   <input type="submit" value="Submit" name="submitwan" onClick="return SubmitWANMode()">
  </td>
 </tr>
 <tr><td><hr size=1 noshade align=top></td></tr>
</table>-->
<div class="data_common data_common_notitle">
<table>
 <tr>
  <th colspan=2><select name="lkname" onChange="on_ctrlupdate()" size="1"></th>
 </tr>
 <tr>
  <th width=30%><% multilang("292" "LANG_ENABLE_VLAN"); %>: </th>
  <td width=70%><input type="checkbox" name="vlan" size="2" maxlength="2" value="ON" onClick=vlanClicked()></td>
 </tr>
 <tr>
  <th><% multilang("293" "LANG_VLAN"); %> ID:</th>
  <td><input type="text" name="vid" size="10" maxlength="15"></td>
 </tr>
 <tr>
  <th><% multilang("319" "LANG_802_1P_MARK"); %> </th>
  <td><select style="WIDTH: 60px" name="vprio">
   <option value="0" > </option>
   <option value="1" > 0 </option>
   <option value="2" > 1 </option>
   <option value="3" > 2 </option>
   <option value="4" > 3 </option>
   <option value="5" > 4 </option>
   <option value="6" > 5 </option>
   <option value="7" > 6 </option>
   <option value="8" > 7 </option>
   </select>
  </td>
 </tr>
 <tr id="multicast_vid_tr" style="display:none">
  <th><% multilang("2751" "LANG_MCAST_VLAN"); %> ID: [1-4095]</th>
  <td><input type="text" id="multicast_vid" name="multicast_vid" size="10" maxlength="15"></td>
 </tr>
 <tr>
  <% ShowChannelMode("ethcmode"); %>
 </tr>
 <% ShowBridgeMode(); %>
 <tr>
  <% ShowNAPTSetting(); %>
 </tr>
 <tr>
  <th <% checkWrite("IPQoS"); %>>
  <% multilang("333" "LANG_ENABLE_QOS"); %>: </th>
  <td><input type="checkbox" name="qosEnabled" size="2" maxlength="2" value="ON" >
  </th>
 </tr>
 <tr>
  <th><% multilang("298" "LANG_ADMIN_STATUS"); %>:</th>
  <td><input type=radio value=1 name="chEnable"><% multilang("255" "LANG_ENABLE"); %>
   <input type=radio value=0 name="chEnable" checked><% multilang("254" "LANG_DISABLE"); %>
  </td>
 </tr>
 <% ShowConnectionType() %>
 <tr id=tbmtu style="display:none">
  <th>MTU:</th>
  <td>
  <input type="text" name="mtu" size="10" maxlength="15">
  </td>
 </tr>
 <tr ID=dgwshow style="display:none">
  <th><% multilang("297" "LANG_DEFAULT_ROUTE"); %>:</th>
  <td>
   <input type=radio value=0 name="droute"><% multilang("254" "LANG_DISABLE"); %>
   <input type=radio value=1 name="droute" checked><% multilang("255" "LANG_ENABLE"); %>
  </td>
 </tr>
 <tr>
  <% ShowIGMPSetting(); %>
 </tr>
 <tr>
  <% ShowMLDSetting(); %>
 </tr>
 <% ShowIpProtocolType(); %>
</table>
</div>
<% ShowPPPIPSettings(); %>
<% ShowDefaultGateway("p2p"); %>
<% Show6rdSetting(); %>
<% ShowIPV6Settings(); %>
<% ShowPortMapping(); %>
<div class="btn_ctl">
<input type="hidden" value="/admin/multi_wan_generic.asp" name="submit-url">
<input type="hidden" id="lst" name="lst" value="">
<input type="hidden" name="encodePppUserName" value="">
<input type="hidden" name="encodePppPassword" value="">
<input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="apply" onClick="return applyCheck(this)">&nbsp; &nbsp; &nbsp; &nbsp;
<input class="link_bg" type="submit" value="<% multilang("315" "LANG_DELETE"); %>" name="delete" onClick="return deleteCheck(this)">
<input type="hidden" name="itfGroup" value=0>
<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 <% DisplayDGW(); %>
 var isConfigRTKRG = <% checkWrite("config_rtk_rg"); %>;
</script>
</form>
</blockquote>
</body>
</html>
