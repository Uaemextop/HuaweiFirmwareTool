<%SendWebHeadStr(); %>
<title><% multilang("1212" "LANG_MULTI_LANGUAL_SETTINGS"); %></title>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("1212" "LANG_MULTI_LANGUAL_SETTINGS"); %></p>
 <p class="intro_content"> <% multilang("1213" "LANG_PAGE_DESC_MULTI_LANGUAL"); %></p>
</div>
<form id="multilangform"action=/boaform/langSel method=POST name="mlSet">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width=30%><% multilang("1214" "LANG_LANGUAGE_SELECT"); %>:</th>
   <td><select size="1" name="selinit"><% checkWrite("selinit"); %></select></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("1215" "LANG_UPDATE_SELECTED_LANGUAGE"); %>" onclick="parent.location.reload();">
</div>
</form>
</body>
</html>
