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
    name: '<% multilang("8" "LANG_WLAN"); %>',
    sub: 3
   },
   {
    name: '<% multilang("11" "LANG_WAN"); %>',
    sub: 4
   },
   {
    name: '<% multilang("1293" "LANG_FIREWALL"); %>',
    sub: 5
   },
   {
    name: '<% multilang("46" "LANG_ADMIN"); %>',
    sub: 8
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
 var sub0, sub1, sub2, sub3, sub4, sub5, sub6, sub7, sub8, sub9;
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
                        href: pageRoot + 'admin/status.asp'
                    }
     ,
                    {
                        name: '<% multilang("5" "LANG_IPV6"); %>',
                        href: pageRoot + 'admin/status_ipv6.asp'
                    }
     ,
     {
      name: '<% multilang("32" "LANG_VOIP"); %>',
      href: pageRoot + 'admin/voip_sip_status_new_web.asp'
     }
     ,
     {
      name: '<% multilang("3072" "LANG_TR069"); %>',
      href: pageRoot + 'status_tr069_info_admin.asp'
     }
                                        ,
                                        {
                                                name: '<% multilang("3073" "LANG_CLIENT_LIST"); %>',
                                                href: pageRoot + 'admin/status_client_list.asp'
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
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlbasic.asp&wlan_idx=0'
     },
     {
      name: '<% multilang("9" "LANG_ADVANCED_SETTINGS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wladvanced.asp&wlan_idx=0'
     },
     {
      name: '<% multilang("1262" "LANG_SECURITY"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwpa.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("1264" "LANG_ACCESS_CONTROL"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlactrl.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("1269" "LANG_SITE_SURVEY"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("1270" "LANG_WPS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwps.asp&wlan_idx=0'
     }
     ,
     {
      name: '<% multilang("3" "LANG_STATUS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlstatus.asp&wlan_idx=0'
     },
     {
      name: '<% multilang("257" "LANG_GUEST_WIFI"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/guest_wifi.asp&wlan_idx=0'
     }
    ]
   },
   {
    collapsed: true,
    name: '<% multilang("1282" "LANG_WLAN1_2_4GHZ"); %>',
    items: [
     {
      name: '<% multilang("1261" "LANG_BASIC_SETTINGS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlbasic.asp&wlan_idx=1'
     },
     {
      name: '<% multilang("9" "LANG_ADVANCED_SETTINGS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wladvanced.asp&wlan_idx=1'
     },
     {
      name: '<% multilang("1262" "LANG_SECURITY"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwpa.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("1264" "LANG_ACCESS_CONTROL"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlactrl.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("1269" "LANG_SITE_SURVEY"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("1270" "LANG_WPS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwps.asp&wlan_idx=1'
     }
     ,
     {
      name: '<% multilang("3" "LANG_STATUS"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/wlstatus.asp&wlan_idx=1'
     },
     {
      name: '<% multilang("257" "LANG_GUEST_WIFI"); %>',
      href: pageRoot + '../boaform/admin/formWlanRedirect?redirect-url=/admin/guest_wifi.asp&wlan_idx=1'
     }
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
      name: '<% multilang("1285" "LANG_PON_WAN"); %>',
      href: pageRoot + '../boaform/admin/formWanRedirect?redirect-url=/admin/multi_wan_generic.asp&if=pon'
     }
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
    name: '<% multilang("1293" "LANG_FIREWALL"); %>',
    items: [
     {
      name: '<% multilang("19" "LANG_MAC_FILTERING"); %>',
      href: pageRoot + 'admin/fw-macfilter.asp'
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
                name: '<% multilang("46" "LANG_ADMIN"); %>',
                items: [
     {
      name: '<% multilang("1309" "LANG_COMMIT_REBOOT"); %>',
      href: pageRoot + 'admin/reboot.asp'
     }
     ,
     {
      name: '<% multilang("1311" "LANG_BACKUP_RESTORE"); %>',
      href: pageRoot + 'admin/saveconf.asp'
     }
     ,
     {
      name: '<% multilang("64" "LANG_SYSTEM_LOG"); %>',
      href: pageRoot + 'admin/syslog.asp'
     }
     ,
     {
      name: '<% multilang("67" "LANG_PASSWORD"); %>',
      href: pageRoot + '/admin/user-password.asp'
     }
     ,
     {
      name: '<% multilang("1313" "LANG_ACL"); %>',
      href: pageRoot + 'admin/acl.asp'
     }
     ,
     {
      name: '<% multilang("69" "LANG_TIME_ZONE"); %>',
      href: pageRoot + 'admin/tz.asp'
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
    side.push(sub0);
    side.push(sub3);
    side.push(sub4);
 side.push(sub5);
 side.push(sub8);
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
