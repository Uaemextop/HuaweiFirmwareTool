<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<title>eSight</title>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" type="text/javascript">

function eSightList(domain, Enable, PlatAddress, PlatExportType) {
    this.domain = domain;
    this.Enable = Enable;
    this.PlatAddress = PlatAddress;
    this.PlatExportType = PlatExportType;
}
var eSightInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_SmartRemoteManage, Enable|PlatAddress|PlatExportType, eSightList);%>;
var eSightInfo = eSightInfos[0];

var isSupportVoip = '<%HW_WEB_GetFeatureSupport(HW_VSPA_FEATURE_VOIP);%>';

function loadlanguage()
{
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length; i++) {
        var b = all[i];
        if (b.getAttribute("BindText") == null) {
            continue;
        }
        setObjNoEncodeInnerHtmlValue(b, esight_language[b.getAttribute("BindText")]);
    }
}

function stInitOption(value, innerText)
{
    this.value = value;
    this.innerText = innerText;
}

function InitDropDownList(id, ArrayOption)
{
    var Control = getElById(id);
    var i = 0;

    for(i = 0; i < ArrayOption.length; i++) {
        var Option = document.createElement("Option");
        Option.value = ArrayOption[i].value;
        Option.innerText = ArrayOption[i].innerText;
        Option.text = ArrayOption[i].innerText;
        Control.appendChild(Option);
    }
}

function InitPlatExportTypeList(id)
{
    var ArrayWanType;

    if (isSupportVoip == 1) {
        ArrayWanType = new Array(new stInitOption("0", "Internet WAN"),
                                 new stInitOption("1", "Voice WAN"),
                                 new stInitOption("2", "TR069 WAN"),
                                 new stInitOption("3", "Other WAN"),
                                 new stInitOption("4", "IPTV WAN"));

    } else {
        ArrayWanType = new Array(new stInitOption("0", "Internet WAN"),
                                 new stInitOption("2", "TR069 WAN"),
                                 new stInitOption("3", "Other WAN"),
                                 new stInitOption("4", "IPTV WAN"));
    }

    InitDropDownList(id, ArrayWanType);
}

function InitDefaultPara()
{
    setCheck('PlatEnable', eSightInfo.Enable);
    setText('PlatAddress', eSightInfo.PlatAddress);
    setSelect('PlatExportType', eSightInfo.PlatExportType);
}

function LoadFrame()
{
    InitPlatExportTypeList("PlatExportType");
    InitDefaultPara();
    loadlanguage();
}

function CheckSubmitPara()
{
    var url = getValue('PlatAddress');
    if (url.length > 256) {
        AlertEx(GetDescFormArrayById(esight_language, "esight009"));
        $("#PlatAddress").focus();
        return false;
    }

    for (var i = 0; i < url.length; i++) {
        var ascicode = url.charAt(i).charCodeAt();
        if ((ascicode > 126) || (ascicode < 33)) {
            AlertEx(GetDescFormArrayById(esight_language, "esight008"));
            $("#PlatAddress").focus();
            return false;
        }
    }

    return true;
}


function SubmitForm()
{
    if (CheckSubmitPara() == false) {
        return;
    }
    var Form = new webSubmitForm();
    Form.addParameter('x.Enable', getCheckVal('PlatEnable'));
    Form.addParameter('x.PlatAddress', getValue('PlatAddress'));
    Form.addParameter('x.PlatExportType', getSelectVal('PlatExportType'));
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));

    Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_SmartRemoteManage&RequestFile=html/ssmp/eSight/eSight.asp');
    setDisable('btnApply', 1);
    setDisable('cancelValue', 1);
    Form.submit();
}

function CancelConfig()
{
    LoadFrame();
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody">
<script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("eSightTitle", GetDescFormArrayById(esight_language, "esight001"), GetDescFormArrayById(esight_language, "esight002"), false);
</script>
<div class="title_spread"></div>

<form id="eSightCfgForm" name="eSightCfgForm">
    <table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
        <li id="PlatEnable" RealType="CheckBox" DescRef="esight003" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.Enable" InitValue="Empty"/>
        <li id="PlatAddress" RealType="TextBox" DescRef="esight004" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.PlatAddress" Elementclass="width_260px" InitValue="Empty"/>
        <li id="PlatExportType" RealType="DropDownList" DescRef="esight005" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.PlatExportType" InitValue="Empty"/>
    </table>
    <script>
        var TableClass = new stTableClass("width_per25", "width_per75", "");
        var eSightCfgFormList = new Array();
        eSightCfgFormList = HWGetLiIdListByForm("eSightCfgForm",null);
        HWParsePageControlByID("eSightCfgForm", TableClass, esight_language, null);
    </script>
</form>
    <table cellpadding="0" cellspacing="0"  width="100%" class="table_button">
    <tr>
        <td class='width_per25'></td>
        <td class="table_submit">
            <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
            <button name="btnApply" id="btnApply" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="SubmitForm();"><script>document.write(esight_language['esight006']);</script></button>
            <button name="cancelValue" id="cancelValue" type="button" class="CancleButtonCss buttonwidth_100px" onClick="CancelConfig();"><script>document.write(esight_language['esight007']);</script></button>
        </td>
    </tr>
    </table>
</body>
</html>
