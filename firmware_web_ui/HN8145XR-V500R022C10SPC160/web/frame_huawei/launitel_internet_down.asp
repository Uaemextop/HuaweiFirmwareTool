<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<link href="/resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" rel="stylesheet" type="text/css" />
<link href="/Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" rel="stylesheet" type="text/css" />
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
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
<title></title>
<script language="JavaScript" type="text/javascript">

var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.HttpsListenInnerPort);%>';

function PPPWANPara(domain, username, Mode, ServiceList, ExServiceList)
{
    this.domain 	= domain;
    this.username 	= username;
    this.Mode       = Mode;
    this.ServiceList = (ExServiceList.length == 0) ? ServiceList : ExServiceList;
}

var wanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i}, Username|ConnectionType|X_HW_SERVICELIST|X_HW_ExServiceList, PPPWANPara);%>;

var pppWanInfo = new Array();

function GetFirstPPPoEWanByType(type)
{
    for(var i = 0;i < wanPpp.length - 1; i++) {
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
            <p style="font-size:25px">
            <script language="JavaScript" type="text/javascript">
            document.write("Your internet connection is not available. Please press the RESET button then wait for 3 minutes till the connection is stable. If you still cannot access the internet, please contact to our Customer Care Services 021999666 for support. Thank you for choosing our services.");

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
			<p style="font-size:25px">
            <script language="JavaScript" type="text/javascript">
            document.write("ການເຊື່ອມຕໍ່ອິນເຕີເນັດຂອງທ່ານບໍ່ສາມາດໃຊ້ໄດ້. ກະລຸນາກົດປຸ່ມ RESET ຈາກນັ້ນລໍຖ້າ 3 ນາທີຈົນກວ່າການເຊື່ອມຕໍ່ຈະ ຫມັ້ນ ຄົງ. ຖ້າທ່ານຍັງບໍ່ສາມາດເຂົ້າເຖິງອິນເຕີເນັດ, ກະລຸນາຕິດຕໍ່ຫາບໍລິການລູກຄ້າຂອງພວກເຮົາ 021999666 ເພື່ອຂໍຄວາມຊ່ວຍເຫຼືອ. ຂອບໃຈທີ່ເລືອກບໍລິການຂອງພວກເຮົາ.");

            if (pppWanInfo.length != 0) {
                document.write('<br>');
                if (pppWanInfo[0].username != "") {
                    document.write("<br> ບັນຊີບໍລິການຂອງທ່ານແມ່ນ: " + htmlencode(pppWanInfo[0].username));
                } else {
                    document.write("<br> ບັນຊີບໍລິການຂອງທ່ານແມ່ນຫວ່າງເປົ່າ");
                }
            }

            </script>
            </p>
            <table width="100%" border="0" cellpadding="0" cellspacing="0">
                <tr>
                <td align="center">
                </td>
                </tr>
            </table>
        </td>
    </tr>
</table>
</body>
</html>