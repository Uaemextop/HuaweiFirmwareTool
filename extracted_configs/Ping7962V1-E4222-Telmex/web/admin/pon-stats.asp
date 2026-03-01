<%SendWebHeadStr(); %>
<meta http-equiv=Refresh CONTENT="10">
<title>PON Statistics</title>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("904" "LANG_PON_STATISTICS"); %></p>
</div>
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th><% multilang("905" "LANG_BYTES_SENT"); %>:</th>
   <td><% ponGetStatus("bytes-sent"); %></td>
  </tr>
  <tr>
   <th><% multilang("906" "LANG_BYTES_RECEIVED"); %>:</th>
   <td><% ponGetStatus("bytes-received"); %></td>
  </tr>
  <tr>
   <th><% multilang("907" "LANG_PACKETS_SENT"); %>:</th>
   <td><% ponGetStatus("packets-sent"); %></td>
  </tr>
  <tr>
   <th><% multilang("908" "LANG_PACKETS_RECEIVED"); %>:</th>
   <td><% ponGetStatus("packets-received"); %></td>
  </tr>
  <tr>
   <th><% multilang("909" "LANG_UNICAST_PACKETS_SENT"); %>:</th>
   <td><% ponGetStatus("unicast-packets-sent"); %></td>
  </tr>
  <tr>
   <th><% multilang("910" "LANG_UNICAST_PACKETS_RECEIVED"); %>:</th>
   <td><% ponGetStatus("unicast-packets-received"); %></td>
  </tr>
  <tr>
   <th><% multilang("911" "LANG_MULTICAST_PACKETS_SENT"); %>:</th>
   <td><% ponGetStatus("multicast-packets-sent"); %></td>
  </tr>
  <tr>
   <th><% multilang("912" "LANG_MULTICAST_PACKETS_RECEIVED"); %>:</th>
   <td><% ponGetStatus("multicast-packets-received"); %></td>
  </tr>
  <tr>
   <th><% multilang("913" "LANG_BROADCAST_PACKETS_SENT"); %>:</th>
   <td><% ponGetStatus("broadcast-packets-sent"); %></td>
  </tr>
  <tr>
   <th><% multilang("914" "LANG_BROADCAST_PACKETS_RECEIVED"); %>:</th>
   <td><% ponGetStatus("broadcast-packets-received"); %></td>
  </tr>
  <tr>
   <th><% multilang("915" "LANG_FEC_ERRORS"); %>:</th>
   <td><% ponGetStatus("fec-errors"); %></td>
  </tr>
  <tr>
   <th><% multilang("916" "LANG_HEC_ERRORS"); %>:</th>
   <td><% ponGetStatus("hec-errors"); %></td>
  </tr>
  <tr>
   <th><% multilang("917" "LANG_PACKETS_DROPPED"); %>:</th>
   <td><% ponGetStatus("packets-dropped"); %></td>
  </tr>
  <tr>
   <th><% multilang("918" "LANG_PAUSE_PACKETS_SENT"); %>:</th>
   <td><% ponGetStatus("pause-packets-sent"); %></td>
  </tr>
  <tr>
   <th><% multilang("919" "LANG_PAUSE_PACKETS_RECEIVED"); %>:</th>
   <td><% ponGetStatus("pause-packets-received"); %></td>
  </tr>
 </table>
</div>
</body>
</html>
