/*
 * cfgtool.c  –  Huawei cfgtool XML configuration utility (reconstructed)
 *
 * Original binary:  /bin/cfgtool  (13920 bytes, ARM32 PIE ELF, stripped)
 * Source filename embedded in .rodata: "hw_cfg_tool.c"
 * Default XML tree: /mnt/jffs2/hw_default_ctree.xml
 *
 * Firmware: EG8145V5-V500R022C00SPC340B019.bin
 * Architecture: ARM32 Cortex-A9, musl libc, EABI5
 *
 * ── .text layout (vaddr, size) ────────────────────────────────────────────
 *  0x1198  780   main()
 *  0x16d0  148   HW_CFGTOOL_ShowUsage()
 *  0x1764  136   HW_CFGTOOL_BatchChangeRet()
 *  0x17ec  132   HW_CFGTOOL_GetOptFile()
 *  0x1870  160   HW_CFGTOOL_GetOptType()
 *  0x1910  348   HW_CFGTOOL_XmlCreate()
 *  0x1a6c  188   HW_CFGTOOL_XmlGet()
 *  0x1b28  188   HW_CFGTOOL_XmlFind()
 *  0x1be4  316   HW_CFGTOOL_XmlGetToFile()
 *  0x1d20   52   HW_CFGTOOL_FreeArgs()
 *  0x1d54  184   HW_CFGTOOL_MallocArgs()
 *  0x1e0c  460   HW_CFGTOOL_CheckArg()
 *  0x1fd8  388   HW_CFGTOOL_OperByType()
 *  0x215c  344   HW_CFGTOOL_GetParaFromString()
 *  0x22b4  840   HW_CFGTOOL_DealBatchType()
 *
 * ── Imported symbols (PLT) ────────────────────────────────────────────────
 *  SSP_ExecShellCmd, strcpy_s, HW_OS_StrCaseCmp, HW_CFGTOOL_CloneXMLValByPath,
 *  HW_OS_Fclose, HW_CFGTOOL_GetXMLValByPath, HW_XML_SetNodeContent,
 *  memcpy, HW_CFGTOOL_SetXMLValByPath, HW_XML_NewNode, HW_OS_Fgets,
 *  HW_OS_StrtokR, HW_XML_FreeSingleNode, HW_OS_StrStr, HW_XML_ParseFile,
 *  HW_CFGTOOL_AddXMLValByPath, HW_CFGTOOL_DelXMLValByPath, HW_OS_Fopen,
 *  HW_OS_Access, HW_CFGTOOL_SysTrace, HW_OS_MemMallocSet, HW_XML_FreeNode,
 *  HW_PROC_DBG_LastWord, HW_OS_CmdFormat, HW_XML_TransformFile, memset_s,
 *  HW_OS_Printf, strncpy_s
 *
 * ── Operation type table (g_stOpTypeTbl at 0xb004, 324 bytes) ────────────
 *  Type 1: "get"    → HW_CFGTOOL_XmlGet
 *  Type 2: "set"    → HW_CFGTOOL_XmlSet (via HW_CFGTOOL_SetXMLValByPath)
 *  Type 3: "find"   → HW_CFGTOOL_XmlFind
 *  Type 4: "add"    → HW_CFGTOOL_XmlAdd (via HW_CFGTOOL_AddXMLValByPath)
 *  Type 5: "create" → HW_CFGTOOL_XmlCreate
 *  Type 6: "del"    → HW_CFGTOOL_XmlDel (via HW_CFGTOOL_DelXMLValByPath)
 *  Type 7: "batch"  → HW_CFGTOOL_DealBatchType
 *  Type 8: "clone"  → HW_CFGTOOL_XmlClone (via HW_CFGTOOL_CloneXMLValByPath)
 *  Type 9: "gettofile" → HW_CFGTOOL_XmlGetToFile
 *
 * ── Usage ─────────────────────────────────────────────────────────────────
 *  cfgtool <op> <xmlfile> <xpath> [value]
 *
 *  Examples:
 *    cfgtool get  /mnt/jffs2/hw_default_ctree.xml "/X_HW_Token/LanEth/Enable"
 *    cfgtool set  /mnt/jffs2/hw_default_ctree.xml "/X_HW_Token/LanEth/Enable" 1
 *    cfgtool find /mnt/jffs2/hw_default_ctree.xml "/X_HW_Token/WLan" "SSID"
 *    cfgtool batch /mnt/jffs2/hw_default_ctree.xml batchfile.txt
 */

#include "hw_cfg_tool.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef STANDALONE_CFGTOOL
/* ── Standalone build: XML ops from cfgtool_xml.c ────────────────────────── */
#  include "cfgtool_xml.h"
#else
/* ── Router / stub-linked build ──────────────────────────────────────────── */
extern void *HW_XML_ParseFile(const char *path, void **node_out);
extern void  HW_XML_FreeNode(void *node);
extern void  HW_XML_FreeSingleNode(void *node);
extern void *HW_XML_NewNode(const char *name);
extern int   HW_XML_SetNodeContent(void *node, const char *content);
extern int   HW_XML_TransformFile(void *node, const char *path);
extern int   HW_CFGTOOL_GetXMLValByPath(void *node, const char *xpath,
                                          char *out, size_t out_sz);
extern int   HW_CFGTOOL_SetXMLValByPath(void *node, const char *xpath,
                                          const char *value);
extern int   HW_CFGTOOL_AddXMLValByPath(void *node, const char *xpath,
                                          const char *value);
extern int   HW_CFGTOOL_DelXMLValByPath(void *node, const char *xpath);
extern int   HW_CFGTOOL_CloneXMLValByPath(void *node, const char *xpath,
                                             const char *dst_xpath);
extern int   HW_CFGTOOL_CheckArg(int op_type, int argc, char **argv);
#endif

/* Host build: safe-string stubs */
#if !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
#  include "hw_os_stubs.h"
#endif

/* ── Huawei OS helpers (stubs on host, libhw_ssp_basic.so on device) ─────── */
extern int   HW_OS_Printf(const char *fmt, ...);
extern void  HW_PROC_DBG_LastWord(int line, const char *file,
                                   const char *msg, int a, int b, int c);
extern void *HW_OS_MemMallocSet(size_t size);
extern void  HW_OS_MemFreeD(void *ptr);
extern int   HW_OS_Access(const char *path, int mode);
extern FILE *HW_OS_Fopen(const char *path, const char *mode);
extern void  HW_OS_Fclose(FILE *fp);
extern char *HW_OS_Fgets(char *buf, int len, FILE *fp);
extern char *HW_OS_StrtokR(char *str, const char *delim, char **saveptr);
extern char *HW_OS_StrStr(const char *hay, const char *needle);
extern int   HW_OS_StrCaseCmp(const char *s1, const char *s2);
extern int   HW_OS_CmdFormat(char *buf, size_t len, const char *fmt, ...);
extern int   SSP_ExecShellCmd(const char *cmd);
extern void  HW_CFGTOOL_SysTrace(const char *file, int line, const char *fmt, ...);

/* ── Constants ──────────────────────────────────────────────────────────── */
#define CFGTOOL_MAX_PATH   0x100   /* 256 bytes, path buffer size */
#define CFGTOOL_BATCH_BUF  0x2000  /* 8 KB, batch file parse buffer */
/* Exact command from V500R022 binary (.rodata at offset 0x2849) */
#define CFGTOOL_RET_CMD \
    "echo %s > /var/cfgtool_ret && chmod 660 /var/cfgtool_ret 2>/dev/null"
#define CFGTOOL_DEFAULT_XML "/mnt/jffs2/hw_default_ctree.xml"
#define CFGTOOL_DEFTREE_KEY "DEFTREE"

/* Operation type IDs are defined in hw_cfg_tool.h (CfgtoolOpType enum) */

/*
 * HW_CFGTOOL_ShowUsage – display usage message to stdout.
 *
 * Disasm (0x16d0 – 0x1763, 148 bytes):
 *   Loads multiple usage strings from .rodata and calls HW_OS_Printf.
 */
void HW_CFGTOOL_ShowUsage(void)
{
    /* Exact usage string from original cfgtool binary at .rodata offset 0x2638 */
    HW_OS_Printf(
        "\n[cfgtool]\n"
        "Usage: cfgtool [OPER] [FILE] [PATH] {AttName and Value}\n"
        "  [OPER] : get/gettofile/set/add/del/batch/create\n"
        "  [FILE] : deftree/[abs path]\n"
        "  [PATH] : as, a.b.c(single-instance) or a.b.c.2(multi-instance)\n"
        "Example:\n"
        "  cfgtool add deftree InternetGatewayDevice.LANDevice.LANDeviceInstance.2\n"
        "  cfgtool del deftree InternetGatewayDevice.LANDevice.LANDeviceInstance.2\n"
        "  cfgtool clone deftree InternetGatewayDevice.Service.VoiceService."
        "VoiceServiceInstance.1 /mnt/jffs2/clone.xml\n"
        "  cfgtool batch deftree /mnt/jffs2/batch.file\n\n");
}

/*
 * HW_CFGTOOL_BatchChangeRet – write operation result code to /var/cfgtool_ret.
 *
 * Disasm (0x1764 – 0x17eb, 136 bytes):
 *   HW_OS_CmdFormat(cmd_buf, 256, CFGTOOL_RET_CMD, result_str)
 *   SSP_ExecShellCmd(cmd_buf)
 */
void HW_CFGTOOL_BatchChangeRet(const char *result_str)
{
    char cmd_buf[CFGTOOL_MAX_PATH];
    HW_OS_CmdFormat(cmd_buf, sizeof(cmd_buf), CFGTOOL_RET_CMD, result_str);
    SSP_ExecShellCmd(cmd_buf);
}

/*
 * HW_CFGTOOL_GetOptFile – resolve XML file path from argv[2].
 *
 * If argv[2] == "DEFTREE", substitute the default ctree path.
 * Otherwise copy argv[2] directly.
 *
 * Disasm (0x17ec – 0x186f, 132 bytes):
 *   HW_OS_StrCaseCmp(argv[2], "DEFTREE")
 *   if equal: strcpy_s(out, "/mnt/jffs2/hw_default_ctree.xml")
 *   else:     strcpy_s(out, argv[2])
 */
int HW_CFGTOOL_GetOptFile(char *out, const char *argv2)
{
    if (HW_OS_StrCaseCmp(argv2, CFGTOOL_DEFTREE_KEY) == 0)
        return strcpy_s(out, CFGTOOL_MAX_PATH, CFGTOOL_DEFAULT_XML);
    return strcpy_s(out, CFGTOOL_MAX_PATH, argv2);
}

/*
 * HW_CFGTOOL_GetOptType – parse operation string from argv[1] to enum.
 *
 * Disasm (0x1870 – 0x190f, 160 bytes):
 *   A series of HW_OS_StrCaseCmp calls matching "get","set","find","add",
 *   "create","del","batch","clone","gettofile".
 *   Returns the matching CfgtoolOpType value, or 0 if unknown.
 */
int HW_CFGTOOL_GetOptType(const char *op_str)
{
    static const struct { const char *name; int type; } ops[] = {
        { "get",       CFGTOOL_OP_GET       },
        { "set",       CFGTOOL_OP_SET       },
        { "find",      CFGTOOL_OP_FIND      },
        { "add",       CFGTOOL_OP_ADD       },
        { "create",    CFGTOOL_OP_CREATE    },
        { "del",       CFGTOOL_OP_DEL       },
        { "batch",     CFGTOOL_OP_BATCH     },
        { "clone",     CFGTOOL_OP_CLONE     },
        { "gettofile", CFGTOOL_OP_GETTOFILE },
        { NULL,        CFGTOOL_OP_NONE      },
    };
    for (int i = 0; ops[i].name; i++)
        if (HW_OS_StrCaseCmp(op_str, ops[i].name) == 0)
            return ops[i].type;
    return CFGTOOL_OP_NONE;
}

/*
 * HW_CFGTOOL_XmlCreate – create a new empty XML document.
 *
 * Disasm (0x1910 – 0x1a6b, 348 bytes):
 *   HW_XML_NewNode("root_node_name")
 *   HW_XML_TransformFile(node, xml_path)
 */
void *HW_CFGTOOL_XmlCreate(const char *xml_path, const char *root_name)
{
    void *node = HW_XML_NewNode(root_name ? root_name : "root");
    if (!node) {
        HW_PROC_DBG_LastWord(0x293, "hw_cfg_tool.c", NULL, 0, 0, 0);
        return NULL;
    }
    if (HW_XML_TransformFile(node, xml_path) != 0) {
        HW_XML_FreeNode(node);
        return NULL;
    }
    return node;
}

/*
 * HW_CFGTOOL_XmlGet – read a node value from an XML file.
 *
 * Disasm (0x1a6c – 0x1b27, 188 bytes):
 *   HW_XML_ParseFile(xml_path, &node)
 *   HW_CFGTOOL_GetXMLValByPath(node, xpath, out_buf, out_sz)
 *   HW_OS_Printf(out_buf)
 *   HW_XML_FreeNode(node)
 */
int HW_CFGTOOL_XmlGet(const char *xml_path, const char *xpath)
{
    void *node  = NULL;
    char  val[CFGTOOL_MAX_PATH];
    int   ret;

    memset(val, 0, sizeof(val));
    if (HW_XML_ParseFile(xml_path, &node) != 0 || !node) {
        HW_PROC_DBG_LastWord(0x28c, "hw_cfg_tool.c", NULL, 0, 0, 0);
        return -1;
    }
    ret = HW_CFGTOOL_GetXMLValByPath(node, xpath, val, sizeof(val));
    if (ret == 0)
        HW_OS_Printf("%s\n", val);
    HW_XML_FreeNode(node);
    return ret;
}

/*
 * HW_CFGTOOL_XmlFind – find child nodes matching a pattern.
 *
 * Disasm (0x1b28 – 0x1be3, 188 bytes):
 *   HW_XML_ParseFile, HW_CFGTOOL_GetXMLValByPath (returns list of matches)
 *   prints each match, frees node.
 */
int HW_CFGTOOL_XmlFind(const char *xml_path, const char *xpath,
                        const char *pattern)
{
    void *node = NULL;
    char  val[CFGTOOL_MAX_PATH];
    int   ret;

    memset(val, 0, sizeof(val));
    if (HW_XML_ParseFile(xml_path, &node) != 0 || !node)
        return -1;

    /* GetXMLValByPath with pattern performs a filtered search in libcfg_api */
    ret = HW_CFGTOOL_GetXMLValByPath(node, xpath, val, sizeof(val));
    if (ret == 0)
        HW_OS_Printf("%s\n", val);
    HW_XML_FreeNode(node);
    return ret;
}

/*
 * HW_CFGTOOL_XmlGetToFile – get node value and write to output file.
 *
 * Disasm (0x1be4 – 0x1d1f, 316 bytes):
 *   Reads val via GetXMLValByPath, opens outfile via HW_OS_Fopen,
 *   writes val, closes outfile.
 */
int HW_CFGTOOL_XmlGetToFile(const char *xml_path, const char *xpath,
                              const char *out_file)
{
    void *node = NULL;
    char  val[CFGTOOL_MAX_PATH];
    FILE *fp;
    int   ret;

    memset(val, 0, sizeof(val));
    if (HW_XML_ParseFile(xml_path, &node) != 0 || !node)
        return -1;

    ret = HW_CFGTOOL_GetXMLValByPath(node, xpath, val, sizeof(val));
    HW_XML_FreeNode(node);

    if (ret != 0) return ret;

    fp = HW_OS_Fopen(out_file, "w");
    if (!fp) return -1;
    HW_OS_Printf("%s", val);   /* also echo to stdout */
    /* write to file (original uses HW_OS_Fopen wrappers, mirrored here) */
    fputs(val, fp);
    HW_OS_Fclose(fp);
    return 0;
}

/*
 * HW_CFGTOOL_FreeArgs – free args array allocated by MallocArgs.
 *
 * Disasm (0x1d20 – 0x1d53, 52 bytes):
 *   HW_OS_MemFreeD(*argv_out), HW_OS_MemFreeD(argv_out)
 */
void HW_CFGTOOL_FreeArgs(char **argv_out, int *argc_out)
{
    if (argv_out) {
        HW_OS_MemFreeD(*argv_out);
        HW_OS_MemFreeD(argv_out);
    }
    (void)argc_out;
}

/*
 * HW_CFGTOOL_MallocArgs – allocate argv-style array for batch parsing.
 *
 * Disasm (0x1d54 – 0x1e0b, 184 bytes):
 *   HW_OS_MemMallocSet(arg_count * sizeof(char*))
 *   HW_OS_MemMallocSet(CFGTOOL_BATCH_BUF) for string storage
 */
int HW_CFGTOOL_MallocArgs(uint32_t max_args, int *argc_out, char ***argv_out)
{
    char **argv = (char **)HW_OS_MemMallocSet(max_args * sizeof(char *));
    char  *buf  = (char *)HW_OS_MemMallocSet(CFGTOOL_BATCH_BUF);

    if (!argv || !buf) {
        HW_OS_MemFreeD(argv);
        HW_OS_MemFreeD(buf);
        return -1;
    }
    *argc_out = 0;
    *argv_out = argv;
    /* Store buf pointer in argv[0] as sentinel for FreeArgs */
    argv[0] = buf;
    return 0;
}

/*
 * HW_CFGTOOL_OperByType – dispatch to per-operation handler.
 *
 * Disasm (0x1fd8 – 0x215b, 388 bytes):
 *   switch(op_type):
 *     case GET/FIND/GETTOFILE: parse file, query, print, save, free
 *     case SET/ADD/DEL/CLONE:  parse file, modify, transform (write back), free
 *     case CREATE:             create new XML, write to file
 *     case BATCH:              HW_CFGTOOL_DealBatchType
 *
 * @param op_type   Operation type (CfgtoolOpType).
 * @param node      Parsed XML node (from HW_XML_ParseFile, may be NULL).
 * @param xml_path  Path to the XML file.
 * @param xml_opt   Second option (xpath or batch-file path).
 * @param arg_count Number of additional arguments.
 * @param args      Additional argument strings.
 * @param extra_buf Work buffer.
 * @return          0 on success.
 */
int HW_CFGTOOL_OperByType(int op_type, void *node,
                            const char *xml_path, const char *xml_opt,
                            int arg_count, char **args, const char *extra_buf)
{
    (void)extra_buf;

    switch (op_type) {
    case CFGTOOL_OP_GET: {
        /* Original: cfgtool get <file> <path> [AttName]
         *   xml_opt = path, args[0] = AttName (optional)
         *   If AttName provided: build full path path.AttName
         */
        if (args && arg_count >= 1 && args[0][0] != '\0') {
            char fullpath[512];
            snprintf(fullpath, sizeof(fullpath), "%s.%s", xml_opt, args[0]);
            return HW_CFGTOOL_XmlGet(xml_path, fullpath);
        }
        return HW_CFGTOOL_XmlGet(xml_path, xml_opt);
    }

    case CFGTOOL_OP_SET: {
        /* Original: cfgtool set <file> <path> <AttName> <Value>
         *   xml_opt = path, args[0] = AttName, args[1] = Value
         *   Build full path: path.AttName, then set Value
         */
        if (!node || !args) return -1;
        if (arg_count >= 2) {
            char fullpath[512];
            snprintf(fullpath, sizeof(fullpath), "%s.%s", xml_opt, args[0]);
            return HW_CFGTOOL_SetXMLValByPath(node, fullpath, args[1]);
        }
        /* Fallback: single arg = direct value set at path */
        return HW_CFGTOOL_SetXMLValByPath(node, xml_opt, args[0]);
    }

    case CFGTOOL_OP_FIND:
        return HW_CFGTOOL_XmlFind(xml_path, xml_opt,
                                    args ? args[0] : NULL);

    case CFGTOOL_OP_ADD:
        if (!node) return -1;
        if (args && arg_count >= 2) {
            /* cfgtool add <file> <path> <childName> <value> */
            char fullpath[512];
            snprintf(fullpath, sizeof(fullpath), "%s.%s", xml_opt, args[0]);
            return HW_CFGTOOL_AddXMLValByPath(node, fullpath, args[1]);
        } else if (args && arg_count >= 1) {
            /* cfgtool add <file> <path> <value> */
            return HW_CFGTOOL_AddXMLValByPath(node, xml_opt, args[0]);
        }
        /* cfgtool add <file> <path> – add empty node */
        return HW_CFGTOOL_AddXMLValByPath(node, xml_opt, NULL);

    case CFGTOOL_OP_CREATE:
        HW_CFGTOOL_XmlCreate(xml_path, xml_opt);
        return 0;

    case CFGTOOL_OP_DEL:
        if (!node) return -1;
        return HW_CFGTOOL_DelXMLValByPath(node, xml_opt);

    case CFGTOOL_OP_CLONE:
        if (!node || !args) return -1;
        return HW_CFGTOOL_CloneXMLValByPath(node, xml_opt, args[0]);

    case CFGTOOL_OP_GETTOFILE:
        return HW_CFGTOOL_XmlGetToFile(xml_path, xml_opt,
                                         args ? args[0] : "/dev/stdout");
    default:
        HW_CFGTOOL_ShowUsage();
        return -1;
    }
}

/*
 * main – cfgtool entry point.
 *
 * Disasm (0x1198 – 0x1477, 780 bytes):
 *
 *   validate argc (needs ≥ 4)
 *   HW_CFGTOOL_GetOptFile(file_buf, argv[2])   → XML file path
 *   strncpy_s(opt_buf, 0xff, argv[3])           → xpath / batch-file
 *   HW_CFGTOOL_GetOptType(argv[1])              → op_type
 *   if op_type == CFGTOOL_OP_CREATE:
 *       HW_CFGTOOL_XmlCreate(file_buf, opt_buf)
 *   else:
 *       HW_XML_ParseFile(file_buf, &node)
 *       HW_CFGTOOL_MallocArgs(0x2000, &argc2, &argv2)
 *       if op_type == CFGTOOL_OP_BATCH:
 *           HW_CFGTOOL_DealBatchType(node, file_buf, opt_buf)
 *       else:
 *           HW_CFGTOOL_CheckArg(op_type, argc, argv)
 *           HW_CFGTOOL_OperByType(op_type, node, ...)
 *       HW_XML_TransformFile(node, file_buf)   [write-back]
 *       HW_XML_FreeNode(node)
 *       HW_CFGTOOL_FreeArgs(argv2, &argc2)
 */
int main(int argc, char **argv)
{
    char  file_buf[CFGTOOL_MAX_PATH];
    char  opt_buf[CFGTOOL_MAX_PATH];
    void *node     = NULL;
    int   op_type;
    int   ret      = -1;

    memset(file_buf, 0, sizeof(file_buf));
    memset(opt_buf,  0, sizeof(opt_buf));

    if (argc < 4) {
        HW_CFGTOOL_ShowUsage();
        HW_CFGTOOL_SysTrace("hw_cfg_tool.c", 0x273,
                             "argc=%d too small, ret=%d", argc, -1);
        return -1;
    }

    /* Resolve XML file path (DEFTREE alias) */
    HW_CFGTOOL_GetOptFile(file_buf, argv[2]);

    /* Copy xpath / option */
    strncpy_s(opt_buf, sizeof(opt_buf) - 1, argv[3], sizeof(opt_buf) - 1);

    /* Parse operation */
    op_type = HW_CFGTOOL_GetOptType(argv[1]);

    if (op_type == CFGTOOL_OP_CREATE) {
        /* Create: build new XML document; no prior parse needed */
        node = HW_CFGTOOL_XmlCreate(file_buf, opt_buf);
        ret  = (node != NULL) ? 0 : -1;
        if (node) HW_XML_FreeNode(node);
    } else {
        /* All other ops: parse existing XML file first.
         * HW_XML_ParseFile returns 0 on success and stores the
         * document handle in *node_out (original API contract). */
        if (HW_XML_ParseFile(file_buf, &node) != 0 || !node) {
            HW_CFGTOOL_ShowUsage();
            HW_CFGTOOL_SysTrace("hw_cfg_tool.c", 0x28c,
                                 "ParseFile failed, ret=%d", ret);
            return -1;
        }

        char **argv2 = NULL;
        int    argc2 = 0;
        if (HW_CFGTOOL_MallocArgs(0x2000, &argc2, &argv2) != 0) {
            HW_XML_FreeNode(node);
            return -1;
        }

        if (op_type == CFGTOOL_OP_BATCH) {
            ret = HW_CFGTOOL_DealBatchType(node, file_buf, opt_buf);
        } else {
            if (HW_CFGTOOL_CheckArg(op_type, argc, argv) == 0) {
                /* Pass argv+4 as the extra args (value, dest, etc.)
                 * Original disasm: OperByType receives argv[4..] as args */
                ret = HW_CFGTOOL_OperByType(op_type, node, file_buf,
                                              opt_buf,
                                              argc > 4 ? argc - 4 : 0,
                                              argc > 4 ? argv + 4 : NULL,
                                              NULL);
            }
        }

        /* Write the modified tree back to the file */
        HW_XML_TransformFile(node, file_buf);
        HW_XML_FreeNode(node);
        HW_CFGTOOL_FreeArgs(argv2, &argc2);
    }

    if (ret != 0)
        HW_CFGTOOL_SysTrace("hw_cfg_tool.c", 0x2b9,
                             "OperByType failed, ret=%d", ret);
    return ret;
}
