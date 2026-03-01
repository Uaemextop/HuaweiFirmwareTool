<%SendWebHeadStr(); %>
<title>ADSL <% multilang("735" "LANG_TONE_MASK"); %><% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
function maskAllClick()
{
   if ( !confirm('<% multilang("2567" "LANG_DO_YOU_REALLY_WANT_TO_MASK_ALL_TONES"); %>') ) {
  return false;
 }
 else
 {
  document.forms[0].maskAll.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
 }
}
function unmaskAllClick()
{
   if ( !confirm('<% multilang("2568" "LANG_DO_YOU_REALLY_WANT_TO_UNMASK_ALL_TONES"); %>') ) {
  return false;
   }
 else
 {
  document.forms[0].unmaskAll.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
 }
}
function applyClick()
{
 document.forms[0].apply.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">ADSL <% multilang("735" "LANG_TONE_MASK"); %> <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"> <% multilang("739" "LANG_THIS_PAGE_LET_USER_TO_MARK_THE_DESIGNATE_TONES_TO_BE_MASKED"); %></p>
</div>
<form action=/boaform/formSetAdslTone method=POST name="formToneTbl">
<% adslToneConfDiagList(); %>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="apply" onClick="return applyClick()">&nbsp;&nbsp;
 <input class="link_bg" type="submit" value="<% multilang("740" "LANG_MASK_ALL"); %>" name="maskAll" onClick="return maskAllClick()">&nbsp;&nbsp;&nbsp;
 <input class="link_bg" type="submit" value="<% multilang("741" "LANG_UNMASK_ALL"); %>" name="unmaskAll" onClick="return unmaskAllClick()">&nbsp;&nbsp;&nbsp;
 <input type="hidden" value="/adsltone.asp" name="submit-url">
 <input class="link_bg" type="button" value="<% multilang("742" "LANG_CLOSE"); %>" name="close" onClick="javascript: window.close();">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
