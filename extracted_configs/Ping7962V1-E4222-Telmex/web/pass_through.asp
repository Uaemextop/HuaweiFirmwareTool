<%SendWebHeadStr(); %>
<title>VPN_PASS_THUR <% multilang("245" "LANG_CONFIGURATION"); %></title>
<script>
function updateIpsecState()
{
    var totalwanNum = document.formVpnPassThru.totalNUM.value;
 var mutli_PassThru1WAN, name;
 for(var i=0;i<totalwanNum;i++){
  name = "mutli_PassThru1WAN_"+i;
  mutli_PassThru1WAN = document.formVpnPassThru.elements[name];
  if(mutli_PassThru1WAN.checked)
   mutli_PassThru1WAN.value = "ON";
  else
   mutli_PassThru1WAN.value = "OFF";
 }
}
function updatePptpState()
{
    var totalwanNum = document.formVpnPassThru.totalNUM.value;
 var mutli_PassThru2WAN;
    for(var i=0;i<totalwanNum;i++){
  var name = "mutli_PassThru2WAN_"+i;
  mutli_PassThru2WAN = document.formVpnPassThru.elements[name];
  if(mutli_PassThru2WAN.checked)
   mutli_PassThru2WAN.value = "ON";
  else
   mutli_PassThru2WAN.value = "OFF";
 }
}
function updateL2tpState()
{
    var totalwanNum = document.formVpnPassThru.totalNUM.value;
 var mutli_PassThru3WAN;
 for(var i=0;i<totalwanNum;i++){
  var name = "mutli_PassThru3WAN_"+i;
  mutli_PassThru3WAN = document.formVpnPassThru.elements[name];
  if(mutli_PassThru3WAN.checked)
   mutli_PassThru3WAN.value = "ON";
  else
   mutli_PassThru3WAN.value = "OFF";
 }
}
</script>
</head>
<body>
<blockquote>
<h2 class="intro_title">VPN PassThrough <% multilang("245" "LANG_CONFIGURATION"); %></h2>
<form action=/boaform/formVpnPassThru method=POST name="formVpnPassThru">
<div class="data_common data_common_notitle">
 <table>
     <tr>
       <td width="10%" align="center">
   <b><% multilang("70" "LANG_INTERFACE"); %></b>
    </td>
    <td width="25%" align="center">
   <b><% multilang("2937" "LANG_ENABLE_IPSEC_PASS_THROUGH_ON_VPN_CONNECTION"); %><b>
    </td>
    <td width="25%" align="center">
   <b><% multilang("2938" "LANG_ENABLE_PPTP_PASS_THROUGH_ON_VPN_CONNECTION"); %><b>
    </td>
    <td width="25%" align="center">
   <b><% multilang("2939" "LANG_ENABLE_L2TP_PASS_THROUGH_ON_VPN_CONNECTION"); %><b>
    </td>
  </tr>
 </table>
</div>
  <% VpnPassThrulist(); %>
<div class="btn_ctl">
<input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>">
<input type="hidden" value="/pass_through.asp" name="submit-url">
</div>
<script>
 <% initPage("VPN PassThr"); %>
</script>
</form>
</blockquote>
</body>
</html>
