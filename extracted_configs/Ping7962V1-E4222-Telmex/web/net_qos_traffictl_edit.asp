<%SendWebHeadStr(); %>
<title><% multilang("802" "LANG_ADD_IP_QOS_TRAFFIC_SHAPING_RULE"); %></title>
<script language="javascript" type="text/javascript">
function on_init_page() {
 if ( <% checkWrite("IPv6Show"); %> )
 {
  if (document.getElementById)
  {
   document.getElementById('ipprotbl').style.display = 'block';
  }
  else {
   if (document.layers == false)
   {
    document.all.ipprotbl.style.display = 'block';
   }
  }
 }
 if ( <% checkWrite("TrafficShapingByVid"); %> )
 {
  if (document.getElementById)
  {
   document.getElementById('vidDiv').style.display = 'block';
  }
  else {
   if (document.layers == false)
   {
    document.all.vidDiv.style.display = 'block';
   }
  }
 }
 if ( <% checkWrite("TrafficShapingBySsid"); %> )
 {
  if (document.getElementById)
  {
   document.getElementById('ssidDiv').style.display = 'block';
  }
  else {
   if (document.layers == false)
   {
    document.all.ssidDiv.style.display = 'block';
   }
  }
 }
}
function on_apply() {
 with(document.forms[0]) {
  if (inflist.value == " ")
  {
   inflist.focus();
   alert("<% multilang("2356" "LANG_WAN_INTERFACE_NOT_ASSIGNED"); %>");
   return;
  }
  if(srcip.value != "" && sji_checkip(srcip.value) == false)
  {
   srcip.focus();
   alert("<% multilang("2357" "LANG_SOURCE_IP_INVALID"); %>");
   return;
  }
  if(dstip.value != "" && sji_checkip(dstip.value) == false)
  {
   dstip.focus();
   alert("<% multilang("2358" "LANG_DESTINATION_IP_INVALID"); %>");
   return;
  }
  if(srcnetmask.value != "" && sji_checkip(srcnetmask.value) == false)
  {
   srcnetmask.focus();
   alert("<% multilang("2359" "LANG_SOURCE_IP_MASK_INVALID"); %>");
   return;
  }
  if(dstnetmask.value != "" && sji_checkip(dstnetmask.value) == false)
  {
   dstnetmask.focus();
   alert("<% multilang("2360" "LANG_DESTINATION_IP_MASK_INVALID"); %>");
   return;
  }
  if(sport.value <0 || sport.value > 65536)
  {
   sport.focus();
   alert("<% multilang("2361" "LANG_SOURCE_PORT_INVALID"); %>");
   return;
  }
  if (sport.value > 0 && sport.value < 65535)
  {
   if (protolist.value!= 1 && protolist.value!= 2 && protolist.value!= 4) {
    sport.focus();
    alert("<% multilang("2362" "LANG_PLEASE_ASSIGN_TCP_UDP"); %>");
    return;
   }
  }
  if(dport.value <0 || dport.value > 65536)
  {
   dport.focus();
   alert("<% multilang("2363" "LANG_DESTINATION_PORT_INVALID"); %>");
   return;
  }
  if (dport.value > 0 && dport.value<65535)
  {
   if (protolist.value!= 1 && protolist.value!= 2 && protolist.value!= 4) {
    dport.focus();
    alert("<% multilang("2362" "LANG_PLEASE_ASSIGN_TCP_UDP"); %>");
    return;
   }
  }
  if(rate.value<0)
  {
   rate.focus();
   alert("<% multilang("2364" "LANG_UPLINK_RATE_INVALID"); %>");
   return;
  }
  if ( <% checkWrite("IPv6Show"); %> ) {
   if(document.forms[0].IpProtocolType.value == 2) {
    if(sip6.value != ""){
     if (! isGlobalIpv6Address(sip6.value) ){
      alert("<% multilang("2329" "LANG_INVALID_SOURCE_IPV6_ADDRESS"); %>");
      return;
     }
     if ( sip6PrefixLen.value != "" ) {
      var prefixlen= getDigit(sip6PrefixLen.value, 1);
      if (prefixlen > 128 || prefixlen <= 0) {
       alert("<% multilang("2330" "LANG_INVALID_SOURCE_IPV6_PREFIX_LENGTH"); %>");
       return;
      }
     }
    }
    if(dip6.value != ""){
     if (! isGlobalIpv6Address(dip6.value) ){
      alert("<% multilang("2331" "LANG_INVALID_DESTINATION_IPV6_ADDRESS"); %>");
      return;
     }
     if ( dip6PrefixLen.value != "" ) {
      var prefixlen= getDigit(dip6PrefixLen.value, 1);
      if (prefixlen > 128 || prefixlen <= 0) {
       alert("<% multilang("2332" "LANG_INVALID_DESTINATION_IPV6_PREFIX_LENGTH"); %>");
       return;
      }
     }
    }
   }
  }
  lst.value ="dummy=dummy&";
  if ( <% checkWrite("TrafficShapingByVid"); %> )
  {
   if( vlanID.value<0 || vlanID.value > 4095){
    alert("<% multilang("2320" "LANG_INCORRECT_VLAN_ID_SHOULE_BE_1_4095"); %>");
    return;
   }
   lst.value += "vlanID="+vlanID.value+"&";
  }
  if ( <% checkWrite("TrafficShapingBySsid"); %> )
  {
    lst.value += "ssid="+ssid.value+"&";
  }
  if ( <% checkWrite("IPv6Show"); %> ) {
   if(document.forms[0].IpProtocolType.value == 1){
    lst.value = lst.value +"inf="+inflist.value+"&proto="+protolist.value+"&IPversion="+IpProtocolType.value+"&srcip="+srcip.value+"&srcnetmask="+srcnetmask.value+
     "&dstip="+dstip.value+"&dstnetmask="+dstnetmask.value+"&sport="+sport.value+"&dport="+dport.value+"&rate="+rate.value+"&direction="+direction.value;
   }
   else if (document.forms[0].IpProtocolType.value == 2) {
    lst.value = lst.value +"inf="+inflist.value+"&proto="+protolist.value+"&IPversion="+IpProtocolType.value+"&sip6="+sip6.value+"&sip6PrefixLen="+sip6PrefixLen.value+
     "&dip6="+dip6.value+"&dip6PrefixLen="+dip6PrefixLen.value+"&sport="+sport.value+"&dport="+dport.value+"&rate="+rate.value+"&direction="+direction.value;
   }
  }
  else
  {
    lst.value = lst.value +"inf="+inflist.value+"&proto="+protolist.value+"&srcip="+srcip.value+"&srcnetmask="+srcnetmask.value+
     "&dstip="+dstip.value+"&dstnetmask="+dstnetmask.value+"&sport="+sport.value+"&dport="+dport.value+"&rate="+rate.value+"&direction="+direction.value;
  }
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  submit();
 }
}
function protocolChange()
{
 if(document.forms[0].IpProtocolType.value == 1){
  if (document.getElementById)
  {
   document.getElementById('ip4tbl').style.display = 'block';
   document.getElementById('ip6tbl').style.display = 'none';
  }
  else {
   if (document.layers == false)
   {
    document.all.ip4tbl.style.display = 'block';
    document.all.ip6tbl.style.display = 'none';
   }
  }
 }
 else if(document.forms[0].IpProtocolType.value == 2){
  if (document.getElementById)
  {
   document.getElementById('ip4tbl').style.display = 'none';
   document.getElementById('ip6tbl').style.display = 'block';
  }
  else {
   if (document.layers == false)
   {
    document.all.ip4tbl.style.display = 'none';
    document.all.ip6tbl.style.display = 'block';
   }
  }
 }
}
</script>
</head>
<body onLoad="on_init_page();">
<div class="intro_main ">
 <p class="intro_title">Add IP QoS Traffic Shaping Rule</p>
 <p class="intro_content"> </p>
</div>
<form id="form" action="/boaform/admin/formQosTraffictlEdit" method="post">
<div id='ipprotbl' style="display:none" class="data_common data_common_notitle">
 <table>
  <tr><th width="30%">IP <% multilang("703" "LANG_VERSION"); %>:</th>
   <td width="70%"><select id="IpProtocolType" onChange="protocolChange()" name="IpProtocolType">
    <option value="1" > IPv4</option>
    <option value="2" > IPv6</option>
    </select>
   </td>
  </tr>
 </table>
</div>
<div id='qos_direction' style="display:<% check_display("qos_direction"); %>" class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("393" "LANG_DIRECTION");%>:</th>
   <td width="70%">
      <select name="direction">
     <option value="0"><% multilang("519" "LANG_UPSTREAM");%></option>
    <% checkWrite("rtk_dev_ap_comment_start"); %>
     <option value="1"><% multilang("518" "LANG_DOWNSTREAM");%> </option>
    <% checkWrite("rtk_dev_ap_comment_end"); %>
      </select>
   </td>
  </tr>
 </table>
</div>
<div id='vidDiv' style="display:none" class="data_common data_common_notitle">
 <table>
  <tr>
    <th width="30%"><% multilang("293" "LANG_VLAN"); %> ID:</th>
   <td width="70%"><input type="text" name="vlanID" size="4" style="width:80px"> </td>
  </tr>
 </table>
</div>
<div id='ssidDiv' style="display:none" class="data_common data_common_notitle">
 <table>
  <tr>
    <th><% multilang("144" "LANG_SSID"); %> ID:</th>
    <td><font size=2><select name="ssid"> <% ssid_list("ssid"); %> </select> </td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th><div id='wan_interface' style="display:<% check_display("wan_interface"); %>" ><% multilang("70" "LANG_INTERFACE"); %>:</div></th>
   <td><div id='wan_interface_value' style="display:<% check_display("wan_interface"); %>" ><select id="inflist"><% if_wan_list("queueITF-without-Any"); %></select></div></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("96" "LANG_PROTOCOL"); %>:</th>
   <td width="70%">
      <select name="protolist">
     <option value="0"><% multilang("353" "LANG_NONE"); %></option>
     <option value="1">TCP </option>
     <option value="2">UDP </option>
     <option value="3">ICMP</option>
<!-- <option value="4">TCP/UDP</option> -->
         </select>
   </td>
  </tr>
 </table>
</div>
<div id='ip4tbl' style="display:block;" class="data_common data_common_notitle">
 <table>
  <tr>
   <th><% multilang("397" "LANG_SOURCE"); %> IP:</th>
   <td><input type="text" name="srcip" size="15" maxlength="15" style="width:150px"></td>
  </tr>
  <tr>
   <th><% multilang("661" "LANG_SOURCE_MASK"); %>:</th>
   <td><input type="text" name="srcnetmask" size="15" maxlength="15" style="width:150px"></td>
  </tr>
  <tr>
   <th><% multilang("398" "LANG_DESTINATION"); %> IP:</th>
   <td><input type="text" name="dstip" size="15" maxlength="15" style="width:150px"></td>
  </tr>
  <tr>
   <th><% multilang("662" "LANG_DESTINATION_MASK"); %>:</th>
   <td><input type="text" name="dstnetmask" size="15" maxlength="15" style="width:150px"></td>
  </tr>
 </table>
</div>
<div id='ip6tbl' style="display:none;" class="data_common data_common_notitle">
 <table>
  <tr>
   <th><% multilang("397" "LANG_SOURCE"); %> IP:</th>
   <td><input type="text" name="sip6" size="26" maxlength="39" style="width:150px"></td>
  </tr>
  <tr>
     <th><% multilang("803" "LANG_SOURCE_PREFIX_LENGTH"); %>:</th>
   <td><input type="text" name="sip6PrefixLen" size="15" maxlength="15" style="width:150px"></td>
  </tr>
  <tr>
    <th><% multilang("398" "LANG_DESTINATION"); %> IP:</th>
   <td><input type="text" name="dip6" size="26" maxlength="39" style="width:150px"></td>
  </tr>
  <tr>
     <th><% multilang("804" "LANG_DESTINATION_PREFIX_LENGTH"); %>:</th>
   <td><input type="text" name="dip6PrefixLen" size="15" maxlength="15" style="width:150px"></td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("400" "LANG_SOURCE_PORT"); %>:</th>
   <td width="70%"><input type="text" name="sport" size="6" style="width:80px"></td>
  </tr>
  <tr>
     <th><% multilang("401" "LANG_DESTINATION_PORT"); %>:</th>
   <td><input type="text" name="dport" size="6" style="width:80px"></td>
  </tr>
  <tr>
    <th><% multilang("793" "LANG_RATE_LIMIT"); %>:</th>
   <td><input type="text" name="rate" size="6" style="width:80px"> kb/s</td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="button" name="return" value="<% multilang("742" "LANG_CLOSE"); %>" onClick="location.href='/net_qos_traffictl.asp';">
 <input class="link_bg" type="button" name="apply" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" onClick="on_apply();">
 <input type="hidden" name="lst" id="lst" value="">
 <input type="hidden" name="submit-url" value="/net_qos_traffictl.asp">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
