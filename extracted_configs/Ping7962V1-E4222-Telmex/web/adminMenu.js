var __GLOBAL__ = {
 pageRoot: ''
};
function generateNav() {
 var navs = {
  active: 0,
  items: [
   {
    name: '<% multilang("3" "LANG_STATUS"); %>',
    sub: 0
   },
   {
    name: '<% multilang("6" "LANG_LAN"); %>',
    sub: 2
   },
   {
    name: '<% multilang("8" "LANG_WLAN"); %>',
    sub: 3
   },
   {
    name: '<% multilang("11" "LANG_WAN"); %>',
    sub: 4
   },
   {
    name: '<% multilang("1277" "LANG_SERVICES"); %>',
    sub: 5
   },
   {
    name: '<% multilang("32" "LANG_VOIP"); %>',
    sub: 6
   },
   {
    name: '<% multilang("1278" "LANG_ADVANCE"); %>',
    sub: 7
   },
   {
    name: '<% multilang("44" "LANG_DIAGNOSTICS"); %>',
    sub: 8
   },
   {
    name: '<% multilang("46" "LANG_ADMIN"); %>',
    sub: 9
   },
   {
    name: '<% multilang("1279" "LANG_STATISTICS"); %>',
    sub: 10
   }
  ]
 };
 return navs;
}
function renderNav() {
 var nav = generateNav();
 var tpl = $('#nav-tmpl').html();
 var html = juicer(tpl, nav);
 $('#nav').html(html);
}
function generateSide() {
 var side = [];
 var sub0, sub1, sub2, sub3, sub4, sub5, sub6, sub7, sub8, sub9, sub10, sub11,sub12;
 var pageRoot = __GLOBAL__.pageRoot;
 sub0 = {
  key: 0,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("3" "LANG_STATUS"); %>',
    items: [
     {
      name: '<% multilang("4" "LANG_DEVICE"); %>',
      href: pageRoot + 'status.asp'
     }
     ,
     {
      name: '<% multilang("5" "LANG_IPV6"); %>',
      href: pageRoot + 'status_ipv6.asp'
     }
     ,
     {
      name: '<% multilang("32" "LANG_VOIP"); %>',
      href: pageRoot + 'voip_sip_status_new_web.asp'
     }
     ,
     {
      name: '<% multilang("3072" "LANG_TR069"); %>',
      href: pageRoot + 'status_tr069_info_admin.asp'
     }
     ,
                                        {
                                                name: '<% multilang("3073" "LANG_CLIENT_LIST"); %>',
      href: pageRoot + 'status_client_list.asp'
                                        }
     ,
     <% CheckMenuDisplay("pon_status"); %>
    ]
   }
  ]
 };
 sub2={
  key:2,
  active:'0-0',
  items:[
   {
    collapsed: false,
    name: '<% multilang("6" "LANG_LAN"); %>',
    items: [
     {
      name: '<% multilang("117" "LANG_LAN_INTERFACE_SETTINGS"); %>',
      href: pageRoot + 'tcpiplan.asp'
     }
     ,
     {
      name: 'LAN VLAN Setup',
      href: pageRoot + 'vlan_translate.asp'
     }
    ]
   }
  ]
 };
 sub3 = {
  key: 3,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("1274" "LANG_WLAN0_5GHZ"); %>',
    items: [
     {
      name: '<% multilang("1261" "LANG_BASIC_SETTINGS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlbasic.asp&wlan_idx=0'
     },
     {
      name: '<% multilang("9" "LANG_ADVANCED_SETTINGS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wladvanced.asp&wlan_idx=0'
     },
     {
      name: '<% multilang("1262" "LANG_SECURITY"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlwpa.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("1264" "LANG_ACCESS_CONTROL"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlactrl.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("1269" "LANG_SITE_SURVEY"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlsurvey.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("1270" "LANG_WPS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlwps.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("3" "LANG_STATUS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlstatus.asp&wlan_idx=0'
     },
                                        {
                                                name: '<% multilang("257" "LANG_GUEST_WIFI"); %>',
                                                href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/guest_wifi.asp&wlan_idx=0'
                                        }
    ]
   },
   {
    collapsed: true,
    name: '<% multilang("1282" "LANG_WLAN1_2_4GHZ"); %>',
    items: [
     {
      name: '<% multilang("1261" "LANG_BASIC_SETTINGS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlbasic.asp&wlan_idx=1'
     },
     {
      name: '<% multilang("9" "LANG_ADVANCED_SETTINGS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wladvanced.asp&wlan_idx=1'
     },
     {
      name: '<% multilang("1262" "LANG_SECURITY"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlwpa.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("1264" "LANG_ACCESS_CONTROL"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlactrl.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("1269" "LANG_SITE_SURVEY"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlsurvey.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("1270" "LANG_WPS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlwps.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("3" "LANG_STATUS"); %>',
      href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/wlstatus.asp&wlan_idx=1'
     },
                                        {
                                                name: '<% multilang("257" "LANG_GUEST_WIFI"); %>',
                                                href: pageRoot + 'boaform/formWlanRedirect?redirect-url=/guest_wifi.asp&wlan_idx=1'
                                        }
    ]
   }
   ,
   {
    collapsed: true,
    name: '<% multilang("1267" "LANG_WLAN_EASY_MESH"); %>',
    items: [
     {
      name: '<% multilang("267" "LANG_WLAN_EASY_MESH_INTERFACE_SETUP"); %>',
      href: pageRoot + 'multi_ap_setting_general.asp'
     }
     <% CheckMenuDisplay("map_topology"); %>
    ]
   }
  ]
 };
 sub4 = {
  key: 4,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("11" "LANG_WAN"); %>',
    items: [
     {
      name: '<% getWanIfDisplay(); %><% multilang("11" "LANG_WAN"); %>',
      href: pageRoot + 'boaform/formWanRedirect?redirect-url=/multi_wan_generic.asp&if=pon'
     },
     <% CheckMenuDisplay("wan_mode"); %>
    ]
   }
  ]
 };
 sub5 = {
  key: 5,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("386" "LANG_SERVICE"); %>',
    items: [
     {
      name: '<% multilang("1288" "LANG_DHCP"); %>',
      href: pageRoot + 'dhcpd.asp'
     }
     ,
     {
      name: '<% multilang("1245" "LANG_DYNAMIC_DNS"); %>',
      href: pageRoot + 'ddns.asp'
     }
     ,
     {
      name: '<% multilang("28" "LANG_IGMP_PROXY"); %>',
      href: pageRoot + 'igmproxy.asp'
     }
     ,
     {
      name: '<% multilang("29" "LANG_UPNP"); %>',
      href: pageRoot + 'upnp.asp'
     }
     ,
     {
      name: '<% multilang("30" "LANG_RIP"); %>',
      href: pageRoot + 'rip.asp'
     }
    ]
   },
   {
    collapsed: true,
    name: '<% multilang("1293" "LANG_FIREWALL"); %>',
    items: [
     {
      name: '<% multilang("1250" "LANG_IP_PORT_FILTERING"); %>',
      href: pageRoot + 'fw-ipportfilter.asp'
     }
     ,
     {
      name: '<% multilang("19" "LANG_MAC_FILTERING"); %>',
      href: pageRoot + 'fw-macfilter.asp'
     }
     ,
     {
      name: '<% multilang("20" "LANG_PORT_FORWARDING"); %>',
      href: pageRoot + 'fw-portfw.asp'
     }
     ,
     {
      name: '<% multilang("1252" "LANG_URL_BLOCKING"); %>',
      href: pageRoot + 'url_blocking.asp'
     }
     ,
     {
      name: '<% multilang("21" "LANG_DOMAIN_BLOCKING"); %>',
      href: pageRoot + 'domainblk.asp'
     }
     ,
     {
      name: '<% multilang("22" "LANG_PARENTAL_CONTROL"); %>',
      href: pageRoot + 'parental-ctrl.asp'
     }
     ,
     {
      name: '<% multilang("1253" "LANG_DMZ"); %>',
      href: pageRoot + 'fw-dmz.asp'
     }
    ]
   }
  ]
 };
 sub6 = {
  key: 6,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("32" "LANG_VOIP"); %>',
    items: [
     {
      name: '<% multilang("1320" "LANG_PORT1"); %>',
      href: pageRoot + 'voip_general_new_web.asp?port=0'
     }
     ,
     {
      name: '<% multilang("1321" "LANG_PORT2"); %>',
      href: pageRoot + 'voip_general_new_web.asp?port=1'
     }
     ,
     {
      name: '<% multilang("1278" "LANG_ADVANCE"); %>',
      href: pageRoot + 'voip_advanced_new_web.asp'
     }
     ,
     {
      name: '<% multilang("33" "LANG_TONE"); %>',
      href: pageRoot + 'voip_tone_new_web.asp'
     }
     ,
     {
      name: '<% multilang("34" "LANG_OTHER"); %>',
      href: pageRoot + 'voip_other_new_web.asp'
     }
     ,
     {
      name: '<% multilang("1324" "LANG_NETWORK"); %>',
      href: pageRoot + 'voip_network_new_web.asp'
     }
     ,
     {
      name: '<% multilang("1242" "LANG_VOIP_CALLHISTORY"); %>',
      href: pageRoot + 'voip_callhistory_new_web.asp'
     }
     ,
     {
      name: '<% multilang("938" "LANG_REGISTER_STATUS"); %>',
      href: pageRoot + 'voip_sip_status_new_web.asp'
     }
    ]
   }
  ]
 };
 sub7 = {
  key: 7,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("1278" "LANG_ADVANCE"); %>',
    items: [
     {
      name: '<% multilang("35" "LANG_ARP_TABLE"); %>',
      href: pageRoot + 'arptable.asp'
     }
     ,
     {
      name: '<% multilang("37" "LANG_BRIDGING"); %>',
      href: pageRoot + 'bridging.asp'
     }
     ,
     {
      name: '<% multilang("3021" "LANG_LOOP_DETECTION"); %>',
      href: pageRoot + 'lbd.asp'
     }
     ,
     {
      name: '<% multilang("38" "LANG_ROUTING"); %>',
      href: pageRoot + 'routing.asp'
     }
     ,
     {
      name: '<% multilang("1296" "LANG_SNMP"); %>',
      href: pageRoot + 'snmp.asp'
     }
     ,
     {
      name: '<% multilang("1300" "LANG_PRINT_SERVER"); %>',
      href: pageRoot + 'printServer.asp'
     }
    ]
   }
   ,
   {
    collapsed: true,
    name: '<% multilang("1298" "LANG_IP_QOS"); %>',
    items: [
     {
      name: '<% multilang("1256" "LANG_QOS_POLICY"); %>',
      href: pageRoot + 'net_qos_imq_policy.asp'
     },
     {
      name: '<% multilang("1255" "LANG_QOS_CLASSIFICATION"); %>',
      href: pageRoot + 'net_qos_cls.asp'
     },
     {
      name: '<% multilang("42" "LANG_TRAFFIC_SHAPING"); %>',
      href: pageRoot + 'net_qos_traffictl.asp'
     }
    ]
   }
   ,
   {
    collapsed: true,
    name: '<% multilang("5" "LANG_IPV6"); %>',
    items: [
     {
      name: '<% multilang("5" "LANG_IPV6"); %> <% multilang("255" "LANG_ENABLE"); %>/<% multilang("254" "LANG_DISABLE"); %>',
      href: pageRoot + 'ipv6_enabledisable.asp'
     }
     ,
     {
      name: '<% multilang("1247" "LANG_RADVD"); %>',
      href: pageRoot + 'radvdconf.asp'
     }
     ,
     {
      name: '<% multilang("1248" "LANG_DHCPV6"); %>',
      href: pageRoot + 'dhcpdv6.asp'
     }
     ,
     {
      name: '<% multilang("26" "LANG_MLD_PROXY"); %>',
      href: pageRoot + 'app_mldProxy.asp'
     }
     ,
     {
      name: '<% multilang("27" "LANG_MLD_SNOOPING"); %>',
      href: pageRoot + 'app_mld_snooping.asp'
     }
     ,
     {
      name: '<% multilang("1249" "LANG_IPV6_ROUTING"); %>',
      href: pageRoot + 'routing_ipv6.asp'
     }
     ,
     {
      name: '<% multilang("1250" "LANG_IP_PORT_FILTERING"); %>',
      href: pageRoot + 'fw-ipportfilter-v6_IfId.asp'
     }
     ,
     {
      name: '<% multilang("1314" "LANG_IPV6_ACL"); %>',
      href: pageRoot + 'aclv6.asp'
     }
    ]
   }
  ]
 };
 sub8 = {
  key: 8,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("44" "LANG_DIAGNOSTICS"); %>',
    items: [
     {
      name: '<% multilang("896" "LANG_PING"); %>',
      href: pageRoot + 'ping.asp'
     }
     ,
     {
                        name: '<% multilang("896" "LANG_PING"); %>6',
                        href: pageRoot + 'ping6.asp'
                    }
                    ,
                    {
                        name: '<% multilang("897" "LANG_TRACERT"); %>',
                        href: pageRoot + 'tracert.asp'
                    }
     ,
                    {
                        name: '<% multilang("897" "LANG_TRACERT"); %>6',
                        href: pageRoot + 'tracert6.asp'
                    }
    ]
   }
  ]
 };
 sub9 = {
  key: 9,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("46" "LANG_ADMIN"); %>',
    items: [
     <% CheckMenuDisplay("pon_settings"); %>
     <% CheckMenuDisplay("omci_info"); %>
     {
      name: '<% multilang("1309" "LANG_COMMIT_REBOOT"); %>',
      href: pageRoot + 'reboot.asp'
     }
     ,
     {
      name: '<% multilang("1311" "LANG_BACKUP_RESTORE"); %>',
      href: pageRoot + 'saveconf.asp'
     }
     ,
     {
      name: '<% multilang("64" "LANG_SYSTEM_LOG"); %>',
      href: pageRoot + 'syslog.asp'
     }
     ,
     {
      name: '<% multilang("67" "LANG_PASSWORD"); %>',
      href: pageRoot + 'password.asp'
     }
     ,
     {
      name: '<% multilang("68" "LANG_FIRMWARE_UPGRADE"); %>',
      href: pageRoot + 'upgrade.asp'
     }
     ,
     {
      name: '<% multilang("1313" "LANG_ACL"); %>',
      href: pageRoot + 'acl.asp'
     }
     ,
     {
      name: '<% multilang("69" "LANG_TIME_ZONE"); %>',
      href: pageRoot + 'tz.asp'
     }
     ,
     {
      name: '<% multilang("1315" "LANG_TR_069"); %>',
      href: pageRoot + 'tr069config_stun.asp'
     }
     ,
     {
      name: '<% multilang("63" "LANG_LOGOUT"); %>',
      href: pageRoot + '/admin/logout.asp'
     }
    ]
   }
  ]
 };
 sub10 = {
  key: 10,
  active: '0-0',
  items: [
   {
    collapsed: false,
    name: '<% multilang("1279" "LANG_STATISTICS"); %>',
    items: [
     {
      name: '<% multilang("70" "LANG_INTERFACE"); %>',
      href: pageRoot + 'stats.asp'
     }
     ,
     <% CheckMenuDisplay("pon_statistics"); %>
    ]
   }
  ]
 };
 side.push(sub0);
 side.push(sub2);
 side.push(sub3);
 side.push(sub4);
 side.push(sub5);
 side.push(sub6);
 side.push(sub7);
 side.push(sub8);
 side.push(sub9);
 side.push(sub10);
 return side;
}
function adaptNav(side, key) {
    key = (key - 0)
        || 0;
    var sideObj = {};
    for (var i = 0; i < side.length; i++) {
        if (side[i] && side[i].key === key) {
            sideObj.active = side[i].active;
            sideObj.items = side[i].items;
            for (var j = 0; j < sideObj.items.length; j++) {
                sideObj.items[j].index = j;
            }
            return sideObj;
        }
    }
}
function renderSide(key) {
    var side = adaptNav(generateSide(), key);
    var tpl = $('#side-tmpl').html();
    var html = juicer(tpl, side);
    $('#side').html(html);
}
function setActive(items, current) {
    $(items).removeClass('active');
    $(current).addClass('active');
}
function setAccordion(item) {
    var $item = $(item);
    var className = 'collapsed';
    var $currentLi = $item.parents('li');
    var $allLi = $item.parents('#side').children('li');
    var $currentContent = $currentLi.children('ul');
    $allLi.addClass(className);
    $currentLi.removeClass(className);
}
