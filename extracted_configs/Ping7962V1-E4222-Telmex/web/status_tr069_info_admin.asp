<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-
<html>
<head>
<title>TR069 Status</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
       <blockquote>
               <div align="left" style="padding-left:20px;"><br>
                       <div align="left"></div>
                       <br>
                       <table class="flat" border="1" cellpadding="1" cellspacing="1">
                               <tr>
                                       <td class="hdb">Proactive reporting Inform Status :</td>
                                       <td><% getInfo("tr069Inform"); %></td>
                               </tr>
                               <tr>
                                       <td class="hdb">Accepting ITMS connection request Status :</td>
                                       <td><% getInfo("tr069Connect"); %></td>
                               </tr>
                       </table>
               </div>
       </blockquote>
</body>
<%addHttpNoCache();%>
</html>
