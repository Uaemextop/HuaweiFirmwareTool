<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<link href="/resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" rel="stylesheet" type="text/css" />
<link href="/Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" rel="stylesheet" type="text/css" />
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script><title></title>
<style>
.prompt_down {
    border: #c5d8e6 1px solid;
    background-color: #feffe0;
    padding: 10px;
    font-family: "Tohama", "Arial", "宋体";
    color: #5c5d55;
    font-size: 12px;
    height: 35px;
}
</style>
<script language="JavaScript" type="text/javascript">

function PPPWANPara(domain,username,Mode,ServiceList,ExServiceList)
{
    this.domain = domain;
    this.username = username;
    this.Mode = Mode;
    this.ServiceList = (ExServiceList.length == 0) ? ServiceList : ExServiceList;
}

var wanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i},Username|ConnectionType|X_HW_SERVICELIST|X_HW_ExServiceList,PPPWANPara);%>;

var pppWanInfo = new Array();

function GetFirstPPPoEWanByType(type)
{
    for(var i = 0; i < wanPpp.length - 1; i++) {
        if ((wanPpp[i].ServiceList == type) && (wanPpp[i].Mode == "IP_Routed")) {
            return wanPpp[i];
        }
    }

    return "";
}

function InitServiceData()
{
    var internet = GetFirstPPPoEWanByType("INTERNET");

    if(internet != "") {
        pppWanInfo.push(internet);
    }
}

InitServiceData();
</script>
</head>

<body>
<br>
<br>
<br>
<br>
<br>
<table width="800" height="100" border="0" cellspacing="0" cellpadding="0" align="center">
    <tr>
        <td class="prompt_down">
            <p  style="font-size:25px">
            <script language="JavaScript" type="text/javascript">
            document.write("Your internet connection is not available due to the lost optical signal. Please contact to our Customer Care Services 021999666 for support. Thank you for choosing our services.");

            if (pppWanInfo.length != 0) {
                document.write('<br>');
                if (pppWanInfo[0].username != "") {
                    document.write("<br> Your service account is: " + htmlencode(pppWanInfo[0].username));
                } else {
                    document.write("<br> Your service account is empty");
                }
            }
            </script>
            </p>
			<p  style="font-size:25px">
            <script language="JavaScript" type="text/javascript">
            document.write("ການເຊື່ອມຕໍ່ ອິນເຕີເນັດ ຂອງທ່ານ ຂັດຂ້ອງ ຊົ່ວຄາວ ເນື່ອງຈາກ ສາຍສົ່ງສັນຍານຖຶກຕັດຂາດ ກະລຸນາ ຕິດຕໍ່ ພາກສ່ວນ ບໍລິການ ລູກຄ້າ ທີ່ເບີ 021 999666 ເພື່ອຊ່ວຍເຫລືອ. ພວກເຮົາຂໍຂອບໃຈທ່ານ ທີ່ເລືອກໃຊ້ ບໍລິການ ຂອງພວກເຮົາ.");

            if (pppWanInfo.length != 0) {
                document.write('<br>');
                if (pppWanInfo[0].username != "") {
                    document.write("<br> ເບີເລກ ບັນຊີ ອິນເຕີເນັດ ຂອງທ່ານຄື: " + htmlencode(pppWanInfo[0].username));
                } else {
                    document.write("<br> ເລກບັນຊີອິນເຕີເນັດຂອງທ່ານແມ່ນຫວ່າງເປົ່າ");
                }
            }
            </script>
            </p>
        </td>
    </tr>
</table>
</body>
</html>