<% SendWebHeadStr();%>
<title>Local Area Network (LAN) VLAN Setup Configuration</title>
<SCRIPT>
var vlan_mapping_interface = <% checkWrite("vlan_mapping_interface"); %>;
function getObj(id)
{
 return(document.getElementById(id));
}
function setValue(id,value)
{
 document.getElementById(id).value=value;
}
function getValue(id)
{
 return(document.getElementById(id).value);
}
function convertDisplay(name,col)
{
 var port = vlan_mapping_interface;
 var mode=["TRUNK mode","Normal mode","VLAN mode"];
 if(col==0){
  return port[name]||"";
 }
 else if(col==1){
  return mode[name]||mode[0];
 }
 else if(col==2){
  return getValue('VLAN'+name);
 }
 return value;
}
function ModifyInstance(obj, index)
{
  var mode_id="Mode"+index;
  if(getValue(mode_id) == 2)
  {
 document.getElementById("Frm_Mode").options[2].selected=true;
 document.getElementById("BindVlanRow").style.display = '';
  }
  else
  {
 if(getValue(mode_id) == 0)
 {
  document.getElementById("Frm_Mode").options[0].selected=true;
 }
 else
 {
  document.getElementById("Frm_Mode").options[1].selected=true;
 }
 document.getElementById("BindVlanRow").style.display = 'none';
  }
  document.getElementById("if_index").value = index;
  document.getElementById("PortId").innerHTML=obj.cells[0].innerText;
  if(obj.cells[2].innerText != "--")
  {
   document.getElementById("VlanPair").value=obj.cells[2].innerText;
  }
  else
  {
    document.getElementById("VlanPair").value='';
  }
  document.getElementById("TableUrlInfo").style.display = "block";
}
function addline(index)
{
 var newline;
 var mode= getValue('Mode'+index);
 var td;
 newline = document.getElementById('Special_Table').insertRow(-1);
 newline.nowrap = true;
 newline.vAlign = "top";
 newline.align = "center";
 newline.onclick = function() {ModifyInstance(this, index)};
 td = newline.insertCell(-1).innerHTML = convertDisplay(index, 0);
 td.width = "10%";
 td = newline.insertCell(-1).innerHTML = convertDisplay(mode,1);
 td.width = "25%";
 td = newline.insertCell(-1).innerHTML = (mode!=2)?"--":convertDisplay(index, 2);
 td.width = "65%";
}
function showTable()
{
 var num = vlan_mapping_interface.length;
 var port = vlan_mapping_interface;
 if (num!=0) {
  for (var i=0; i<num; i++) {
   if (port[i] == "SSID_DISABLE") {
    continue;
   }
   addline(i);
  }
 }
 else {
 }
}
function on_init()
{
 showTable();
}
function checkVLANRange(vlan)
{
 var num = reservedVlanA.length;
 for(var i = 0; i<num; i++){
  if(vlan == reservedVlanA[i])
   return false;
 }
 if(sji_checkdigitrange(vlan, otherVlanStart, otherVlanEnd) == true)
  return false;
 return true;
}
function OnChooseDeviceType(Select)
{
   var Mode = document.getElementById("Frm_Mode").value;
   if (Mode == "0")
       document.getElementById("BindVlanRow").style.display = 'none';
   else if (Mode == "1")
       document.getElementById("BindVlanRow").style.display = 'none';
   else if (Mode == "2")
       document.getElementById("BindVlanRow").style.display = '';
}
function OnCancelButtonClick()
{
    document.getElementById("TableUrlInfo").style.display = "none";
    return false;
}
function OnApplyButtonClick()
{
 if(2 == document.getElementById("Frm_Mode").value)
 {
  var BindVlan = document.getElementById("VlanPair").value;
  if(false == IsBindBindVlanValid(BindVlan))
  {
   return false;
  }
 }
 document.forms[0].submit();
 return true;
}
function IsBindBindVlanValid(BindVlan)
{
 var LanVlanWanVlanList = BindVlan.split(",");
 var LanVlan;
 var WanVlan;
 var TempList;
 var i;
 if ( LanVlanWanVlanList.length > 8)
 {
   alert("Max support four VLAN pairs");
   return false;
 }
 var SortLanVlanWanVlanList=LanVlanWanVlanList.sort();
 for (i = 0; i < LanVlanWanVlanList.length-1; i++)
 {
  if (SortLanVlanWanVlanList[i]==SortLanVlanWanVlanList[i+1])
  {
   alert(BindVlan+" has duplicated setting");
   return false;
  }
 }
 for (i = 0; i < LanVlanWanVlanList.length; i++)
 {
  TempList = LanVlanWanVlanList[i].split("/");
  if (TempList.length != 2)
  {
   alert(BindVlan+"format invalid");
   return false;
  }
  if ((isNaN(parseInt(TempList[0]))) || (isNaN(parseInt(TempList[1]))))
  {
   alert(BindVlan+"format invalid");
   return false;
  }
  if (!(parseInt(TempList[0]) >= 1 && parseInt(TempList[0]) <= 4095))
  {
   alert(BindVlan+"Vlan\""+parseInt(TempList[0])+"\"invalid");
   return false;
  }
  if (!(parseInt(TempList[1]) >= -1 && parseInt(TempList[1]) <= 7))
  {
   alert(BindVlan+" Vlan priority\""+parseInt(TempList[1])+"\"invalid (valid:0~7, '-1':not assigned)");
   return false;
  }
 }
 document.getElementById("Frm_VLANPRI").value = BindVlan;
 return true;
}
</script>
</head>
<!-------------------------------------------------------------------------------------->
<!--翋珜測鎢-->
<body onLoad="on_init();">
    <div class="intro_main ">
  <p class="intro_title">Local Area Network (LAN) VLAN Setup <%multilang("245" "LANG_CONFIGURATION");%></p>
  <p class="intro_content">You can setup LAN's vlan/priority pair here.
  The value of vlan/priority is set in M1/N1 pairs,
  where M1 represents the vlan on LAN, N1 represents the vlan priority of LAN,
  and multiple groups of vlan-priority pairs are separated by ',' ex: 100/1,200/2.</p>
 </div>
 <div class="data_common data_common_notitle">
  <table width=600 id="Special_Table">
    <tr>
      <th width=600>Coniguration <% multilang("109" "LANG_STATUS_1"); %></th>
    </tr>
    <tr>
      <td width="10%">Port</td>
      <td width="25%">Mode</td>
      <td width="65%">VLAN Coniguration</td>
    </tr>
  </table>
        <!--Apply睿Cancel偌聽-->
        <div id="TableUrlInfo" style="display:none">
        <form id="vmap" action=/boaform/admin/formLanVlanSetup method=POST name=vmap>
          <table width=600 class="table1_bg" border="1">
            <tbody>
            <tr>
     <th colspan="2" bgcolor="#C0C0C0"><strong>VLAN Setting</strong></th>
     </tr>
             <tr>
              <td bgcolor="#DDDDDD" align="left" width="25%" >Port
              </td><td bgcolor="#DDDDDD" width="75%"><div id="PortId"></div></td>
              </tr>
         <tr>
              <td bgcolor="#DDDDDD" align="left" width="25%" class="table1_left">Mode</td>
              <td bgcolor="#DDDDDD" class="table1_right"><select name="Frm_Mode" id="Frm_Mode" onchange="OnChooseDeviceType(this);">
                  <option value="0">Trunk </option>
      <option value="1">Normal</option>
      <option value="2">Enable VLAN</option>
                </select></td>
            </tr>
          </tbody></table>
          <div id="BindVlanRow">
            <table width=600 class="table1_bg" border="1">
              <tbody><tr>
                <td bgcolor="#DDDDDD" width="25%" align="left" class="table1_left">Setup VLAN/Priority</td>
                <td bgcolor="#DDDDDD" class="table1_right"><input type="text" id="VlanPair" style="width:300px" maxlength="255"></td>
              </tr>
            </tbody></table>
          </div>
    </div>
          <table id="ConfigPanelButtons" width=600 cellspacing="1" class="table1_button">
            <tbody>
            <tr align="center">
              <td class="table1_submit" style="padding-left: 5px"><input type="hidden" value="0" name="entryidx">
    <input type='hidden' id="Frm_Mode" name="Frm_Mode" type="text" value="">
    <input type='hidden' id="Frm_VLANPRI" name="Frm_VLANPRI" type="text" value="">
    <input type='hidden' name=if_index ID=if_index value=''>
    <input type="hidden" name="submit-url" value="/vlan_translate.asp">
    <div class="btn_ctl">
    <input type="submit" value="Apply" name="save" onClick="return OnApplyButtonClick()" class="link_bg">&nbsp;&nbsp;
    <input type="submit" value="Cancel" name="save" onClick="return OnCancelButtonClick()" class="link_bg">
    </div>
            </tr>
          </tbody>
          </table>
          </form>
           <input type='hidden' name=if_instnum ID=if_instnum value=14>
    <input type='hidden' name=Mode0 ID=Mode0 value='0'>
    <input type='hidden' name=VLAN0 ID=VLAN0 value=''>
    <input type='hidden' name=Mode1 ID=Mode1 value='0'>
    <input type='hidden' name=VLAN1 ID=VLAN1 value=''>
    <input type='hidden' name=Mode2 ID=Mode2 value='0'>
    <input type='hidden' name=VLAN2 ID=VLAN2 value=''>
    <input type='hidden' name=Mode3 ID=Mode3 value='0'>
    <input type='hidden' name=VLAN3 ID=VLAN3 value=''>
    <input type='hidden' name=Mode4 ID=Mode4 value='0'>
    <input type='hidden' name=VLAN4 ID=VLAN4 value=''>
    <input type='hidden' name=Mode5 ID=Mode5 value='0'>
    <input type='hidden' name=VLAN5 ID=VLAN5 value=''>
    <input type='hidden' name=Mode6 ID=Mode6 value='0'>
    <input type='hidden' name=VLAN6 ID=VLAN6 value=''>
    <input type='hidden' name=Mode7 ID=Mode7 value='0'>
    <input type='hidden' name=VLAN7 ID=VLAN7 value=''>
    <input type='hidden' name=Mode8 ID=Mode8 value='0'>
    <input type='hidden' name=VLAN8 ID=VLAN8 value=''>
    <input type='hidden' name=Mode9 ID=Mode9 value='0'>
    <input type='hidden' name=VLAN9 ID=VLAN9 value=''>
    <input type='hidden' name=Mode10 ID=Mode10 value='0'>
    <input type='hidden' name=VLAN10 ID=VLAN10 value=''>
    <input type='hidden' name=Mode11 ID=Mode11 value='0'>
    <input type='hidden' name=VLAN11 ID=VLAN11 value=''>
    <input type='hidden' name=Mode12 ID=Mode12 value='0'>
    <input type='hidden' name=VLAN12 ID=VLAN12 value=''>
    <input type='hidden' name=Mode13 ID=Mode13 value='0'>
    <input type='hidden' name=VLAN13 ID=VLAN13 value=''>
    <script>
    <% initPageLanVlan(); %>
    </script>
        </div>
      </td>
      </tr>
   </tbody>
   </table>
 <blockquote>
</body>
<%addHttpNoCache();%>
</html>
