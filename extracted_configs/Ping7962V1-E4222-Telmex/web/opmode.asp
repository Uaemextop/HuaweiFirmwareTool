<% SendWebHeadStr();%>
<title><% multilang(LANG_INTERNET_OP_MODE); %></title>
<SCRIPT>
var isCMCCSupport = <% checkWrite("isCMCCSupport"); %>;
function saveChanges()
{
 document.forms[0].save.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function enabledgateway()
{
 document.Internetmode.opmode[0].checked = true;
 document.Internetmode.opmode.value=0;
}
function enabledbridge()
{
 document.Internetmode.opmode[1].checked = true;
 document.Internetmode.opmode.value=1;
}
function enabledrepeater()
{
 document.Internetmode.opmode[2].checked = true;
 document.Internetmode.opmode.value=3;
}
function on_init()
{
 var opmode = <% checkWrite("Internet OP Mode"); %>;
 if(opmode == 0){
  document.Internetmode.opmode[0].checked = true;
  document.Internetmode.opmode[1].checked = false;
  if(isCMCCSupport==1)
   document.Internetmode.opmode[2].checked = false;
 }else if(opmode ==1){
  document.Internetmode.opmode[0].checked = false;
  document.Internetmode.opmode[1].checked = true;
  if(isCMCCSupport==1)
   document.Internetmode.opmode[2].checked = false;
 }else if(isCMCCSupport==1 && opmode ==3){
  document.Internetmode.opmode[0].checked = false;
  document.Internetmode.opmode[1].checked = false;
  document.Internetmode.opmode[2].checked = true;
 }
 return true;
}
</SCRIPT>
</head>
<BODY onLoad="on_init();">
 <div class="intro_main ">
  <p class="intro_title"><% multilang("2989" "LANG_OPERATION_MODE"); %></p>
  <p class="intro_content"><% multilang("2992" "LANG_PAGE_DESC_CONFIGURE_INTERNET_OP_MODE_SETTING") %></p>
 </div>
<form action=/boaform/formInternetMode method=POST name="Internetmode">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th><% multilang("2989" "LANG_OPERATION_MODE"); %>:</th>
   <td>
   <% checkWrite("InternetMode"); %>
   </td>
  </tr>
 </table>
</div>
</td>
      <input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return saveChanges()">&nbsp;&nbsp;
   <input type="hidden" value="/opmode.asp" name="submit-url">
   <input type="hidden" name="postSecurityFlag" value="">
</td>
<br><br>
</form>
</body>
</html>
