/*
 * cfgtool_xml.c  –  Standalone XML engine for cfgtool
 *
 * Decompiled from original Huawei firmware binaries:
 *   - cfgtool (ARM32 PIE ELF, 13920 bytes, V500R022C00SPC340B019)
 *   - libhw_ssp_basic.so (903 KB) → HW_XML_* functions
 *   - libsmp_api.so (324 KB) → HW_CFGTOOL_*XMLValByPath functions
 *
 * Original node structure (from disassembly of libhw_ssp_basic.so):
 *   offset 0x00: parent pointer
 *   offset 0x04: prev sibling
 *   offset 0x08: next sibling
 *   offset 0x0C: first child
 *   offset 0x10: last child
 *   offset 0x14: first attr
 *   offset 0x18: last attr
 *   offset 0x1C: uint16 child_count
 *   offset 0x1E: uint8 attr_count
 *   offset 0x1F: uint8 type (0xC = attribute type in GetAttrNode)
 *   offset 0x20: char *name
 *   offset 0x24: char *value
 *   offset 0x28: char *content (used by GetAttrValue)
 *
 * This file implements the same node structure and operations using
 * libxml2 as the underlying XML parser, replacing the proprietary
 * Huawei XML engine while preserving identical behavior.
 *
 * Dot-path format (from cfgtool usage string in binary):
 *   a.b.c          → single instance: <a><b><c>
 *   a.b.c.2        → multi-instance:  <a><b><c>[2nd sibling]
 *   DEFTREE        → alias for /mnt/jffs2/hw_default_ctree.xml
 *
 * Compile: requires libxml2 (-lxml2 -I/usr/include/libxml2).
 */

#include "cfgtool_xml.h"
#include "hw_cfg_tool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/* ── Helpers from hw_os_stubs / cfgtool ──────────────────────────────────── */
extern int  HW_OS_Printf(const char *fmt, ...);
extern void HW_PROC_DBG_LastWord(int line, const char *file,
                                  const char *msg, int a, int b, int c);
extern void HW_CFGTOOL_SysTrace(const char *file, int line,
                                  const char *fmt, ...);
extern void *HW_OS_MemMallocSet(size_t size);
extern void  HW_OS_MemFreeD(void *ptr);
extern FILE *HW_OS_Fopen(const char *path, const char *mode);
extern void  HW_OS_Fclose(FILE *fp);
extern char *HW_OS_Fgets(char *buf, int len, FILE *fp);
extern char *HW_OS_StrtokR(char *str, const char *delim, char **saveptr);
extern int   HW_OS_StrCaseCmp(const char *s1, const char *s2);
extern int   HW_OS_CmdFormat(char *buf, size_t len, const char *fmt, ...);
extern int   SSP_ExecShellCmd(const char *cmd);

/* ======================================================================== */
/*  HW_CFGTOOL_CheckDigitStr  –  decompiled from libsmp_api.so @ 0x35d8c    */
/*                                                                           */
/*  Original: 132 bytes ARM32.  Checks if a string is all-digit.             */
/*  r0 = string, r1 = out_flag.  Sets *out_flag = 1 if all digits, else 0. */
/* ======================================================================== */
static int HW_CFGTOOL_CheckDigitStr(const char *str, int *out_flag)
{
    if (!str || !out_flag) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x7e,
                             "null param %p %p", 0, 0);
        return -1;
    }

    *out_flag = 1;
    const char *p = str;
    while (*p) {
        if ((unsigned char)(*p - '0') > 9) {
            *out_flag = 0;
            break;
        }
        p++;
    }
    return 0;
}

/* ======================================================================== */
/*  Path navigation helpers  –  decompiled from libsmp_api.so               */
/*                                                                           */
/*  The original GetNodeByPath (1028 bytes @ 0x36084) navigates the XML     */
/*  tree using dot-separated path components.  Numeric components select     */
/*  the N-th sibling with the same tag (1-based).                            */
/*                                                                           */
/*  The implementation below replicates the exact same behavior using        */
/*  libxml2's tree structure instead of Huawei's proprietary node format.    */
/* ======================================================================== */

/*
 * navigate_to_node – walk down an xmlNodePtr tree following a dot-path.
 *
 * Mirrors HW_CFGTOOL_GetNodeByPath logic (libsmp_api.so @ 0x36084, 1028 bytes):
 *   For each dot-separated component:
 *     - If it's all digits → multi-instance selector
 *       Select the N-th sibling with the same tag as the PREVIOUS component
 *       (1-based index).  This is how the original binary handles paths like:
 *       WANConnectionDevice.WANPPPConnection.2 → 2nd WANPPPConnection
 *     - Else → named element: find first child with matching name
 *
 * @param root     Root element (xmlNodePtr)
 * @param dotpath  Dot-separated path (e.g. "DeviceInfo.Manufacturer")
 * @param create   If nonzero, create missing intermediate elements
 * @return         Target node, or NULL if not found
 */
static xmlNodePtr navigate_to_node(xmlNodePtr root, const char *dotpath,
                                    int create)
{
    if (!root || !dotpath || !*dotpath) return root;

    char *path_dup = strdup(dotpath);
    if (!path_dup) return NULL;

    xmlNodePtr cur = root;
    char *saveptr = NULL;
    char *prev_token = NULL;
    char *token = strtok_r(path_dup, ".", &saveptr);

    while (token && cur) {
        int is_digit = 1;
        HW_CFGTOOL_CheckDigitStr(token, &is_digit);

        if (is_digit && *token && prev_token) {
            /* Multi-instance index: select the N-th sibling element that
             * has the same tag as the current node (prev_token).
             *
             * Original GetNodeByPath logic: when path component is numeric,
             * go back to the parent and find the N-th child with the same tag.
             * E.g., "WANPPPConnection.2" → 2nd <WANPPPConnection> sibling. */
            int idx = atoi(token);
            const char *sibling_tag = (const char *)cur->name;
            xmlNodePtr parent_node = cur->parent;
            if (!parent_node) { cur = NULL; break; }

            int count = 0;
            xmlNodePtr found = NULL;
            for (xmlNodePtr c = parent_node->children; c; c = c->next) {
                if (c->type == XML_ELEMENT_NODE &&
                    strcmp((const char *)c->name, sibling_tag) == 0) {
                    count++;
                    if (count == idx) {
                        found = c;
                        break;
                    }
                }
            }
            if (!found && create) {
                while (count < idx) {
                    found = xmlNewChild(parent_node, NULL,
                                         (const xmlChar *)sibling_tag, NULL);
                    count++;
                }
            }
            cur = found;
        } else {
            /* Named element: find first child element with matching name.
             * Matches original GetNodeByPath which iterates children
             * using HW_XML_GetFirstChild / HW_XML_GetNextNode and
             * compares name via strcmp at offset 0x20 */
            xmlNodePtr found = NULL;
            for (xmlNodePtr c = cur->children; c; c = c->next) {
                if (c->type == XML_ELEMENT_NODE &&
                    strcmp((const char *)c->name, token) == 0) {
                    found = c;
                    break;
                }
            }
            if (!found && create) {
                found = xmlNewChild(cur, NULL, (const xmlChar *)token, NULL);
            }
            cur = found;
        }

        prev_token = token;
        token = strtok_r(NULL, ".", &saveptr);
    }

    free(path_dup);
    return cur;
}

/*
 * split_last_component – split "a.b.c" into parent="a.b" and leaf="c"
 *
 * Mirrors HW_CFGTOOL_SplitPath (libsmp_api.so @ 0x36c08, 404 bytes).
 */
static int split_last_component(const char *dotpath,
                                  char *parent_out, size_t parent_sz,
                                  char *leaf_out, size_t leaf_sz)
{
    if (!dotpath || !*dotpath) return -1;

    const char *last_dot = strrchr(dotpath, '.');
    if (!last_dot) {
        if (parent_out) parent_out[0] = '\0';
        snprintf(leaf_out, leaf_sz, "%s", dotpath);
        return 0;
    }

    size_t plen = (size_t)(last_dot - dotpath);
    if (plen >= parent_sz) return -1;
    memcpy(parent_out, dotpath, plen);
    parent_out[plen] = '\0';
    snprintf(leaf_out, leaf_sz, "%s", last_dot + 1);
    return 0;
}

/*
 * resolve_root_path – check if path starts with root element name.
 *
 * On the router, cfgtool paths start from the root element name
 * (e.g. "InternetGatewayDevice.WANDevice...").
 * This helper strips the root name prefix and returns the remainder.
 *
 * Returns: pointer to the path after the root name (may be empty string),
 *          or the original dotpath if it doesn't start with root name.
 */
static const char *resolve_root_path(xmlNodePtr root, const char *dotpath,
                                       char *buf, size_t bufsz)
{
    if (!root || !dotpath) return dotpath;

    const char *root_name = (const char *)root->name;
    size_t rlen = strlen(root_name);

    if (strncmp(dotpath, root_name, rlen) == 0) {
        if (dotpath[rlen] == '.') {
            return dotpath + rlen + 1;
        } else if (dotpath[rlen] == '\0') {
            return "";
        }
    }

    /* Path doesn't start with root name — use as-is from root's children */
    return dotpath;
}

/* ======================================================================== */
/*  HW_XML_* implementations  –  decompiled from libhw_ssp_basic.so         */
/* ======================================================================== */

/*
 * HW_XML_ParseFile  –  wrapper at 0xa47c8 (8 bytes):
 *   mov r2, #0; b HW_XML_ParseFile_Ex
 *
 * HW_XML_ParseFile_Ex at 0xa46dc (236 bytes):
 *   Opens file, reads content, calls internal XML parser.
 *   Returns 0 on success, stores document node in *node_out.
 *   The node_out pointer is the primary handle used by all other operations.
 *
 * Standalone replacement: use xmlReadFile from libxml2.
 * Returns 0 on success.  Stores xmlDocPtr in *node_out (cast to void*).
 * The xmlDocPtr serves as the opaque handle for all operations.
 */
void *HW_XML_ParseFile(const char *path, void **node_out)
{
    if (!path) {
        if (node_out) *node_out = NULL;
        return (void *)(intptr_t)-1;
    }

    xmlDocPtr doc = xmlReadFile(path, NULL,
                                XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        if (node_out) *node_out = NULL;
        return (void *)(intptr_t)-1;
    }

    /* Store the doc pointer in *node_out — this is what the caller uses
     * as the handle for all subsequent operations (get/set/add/del/etc.)
     * and for FreeNode/TransformFile. */
    if (node_out)
        *node_out = (void *)doc;

    /* Return 0 on success (original contract from disassembly) */
    return NULL;  /* 0 = success */
}

/*
 * HW_XML_FreeNode  –  wrapper at 0xa1da0 (8 bytes):
 *   mov r1, #0; b HW_XML_FreeNode_Ex
 *
 * HW_XML_FreeNode_Ex at 0xa1d5c (68 bytes):
 *   Recursively frees node and all children.
 */
void HW_XML_FreeNode(void *node)
{
    if (!node) return;

    /* The handle from ParseFile is xmlDocPtr */
    xmlDocPtr doc = (xmlDocPtr)node;
    if (doc->type == XML_DOCUMENT_NODE) {
        xmlFreeDoc(doc);
    } else {
        xmlFreeNode((xmlNodePtr)node);
    }
}

/*
 * HW_XML_FreeSingleNode  –  wrapper at 0xa1344 (8 bytes):
 *   Unlinks from parent, then frees just this node and its subtree.
 *
 * Original (0xa1600, RemoveAttrNode, 96 bytes):
 *   Updates prev/next/parent pointers, decrements child_count.
 */
void HW_XML_FreeSingleNode(void *node)
{
    if (node) {
        xmlNodePtr n = (xmlNodePtr)node;
        xmlUnlinkNode(n);
        xmlFreeNode(n);
    }
}

/*
 * HW_XML_NewNode  –  wrapper at 0xa1290 (8 bytes):
 *   mov r1, #0; b HW_XML_NewNode_Ex
 *
 * HW_XML_NewNode_Ex at 0xa1254 (60 bytes):
 *   Allocates a new node, sets name, initializes all pointers to NULL.
 *
 * Returns: xmlDocPtr containing a new root element.
 */
void *HW_XML_NewNode(const char *name)
{
    if (!name) name = "root";

    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (!doc) return NULL;

    xmlNodePtr root = xmlNewNode(NULL, (const xmlChar *)name);
    if (!root) {
        xmlFreeDoc(doc);
        return NULL;
    }
    xmlDocSetRootElement(doc, root);
    return (void *)doc;
}

/*
 * HW_XML_SetNodeContent  –  at 0xa1bd8 (36 bytes):
 *   Calls SetNodeContent_Ex with extra param = 0.
 *
 * SetNodeContent_Ex at 0xa19dc (508 bytes):
 *   Frees old value string, allocates and copies new value.
 *   Sets node->value (offset 0x24) to the new string.
 */
int HW_XML_SetNodeContent(void *node, const char *content)
{
    if (!node) return -1;
    xmlNodePtr n = (xmlNodePtr)node;
    xmlNodeSetContent(n, (const xmlChar *)(content ? content : ""));
    return 0;
}

/*
 * HW_XML_TransformFile  –  at 0xa512c (216 bytes):
 *   Serializes the XML tree to a file.
 *   Opens file with HW_OS_Fopen("w"), writes XML declaration,
 *   recursively writes elements, closes file.
 */
int HW_XML_TransformFile(void *node, const char *path)
{
    if (!node || !path) return -1;

    xmlDocPtr doc;
    if (((xmlNodePtr)node)->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr)node;
    } else {
        doc = ((xmlNodePtr)node)->doc;
    }
    if (!doc) return -1;

    int ret = xmlSaveFormatFileEnc(path, doc, "UTF-8", 1);
    return (ret >= 0) ? 0 : -1;
}

/* ======================================================================== */
/*  HW_CFGTOOL_*XMLValByPath  –  decompiled from libsmp_api.so              */
/*                                                                           */
/*  These are the core cfgtool operations that navigate XML by dot-path.     */
/*  Original sizes (from dynsym):                                            */
/*    GetXMLValByPath:   460 bytes @ 0x37500                                 */
/*    SetXMLValByPath:   496 bytes @ 0x37310                                 */
/*    AddXMLValByPath:   644 bytes @ 0x36ec0                                 */
/*    DelXMLValByPath:   460 bytes @ 0x37144                                 */
/*    CloneXMLValByPath: 500 bytes @ 0x376cc                                 */
/* ======================================================================== */

/*
 * HW_CFGTOOL_GetXMLValByPath  –  get value at dot-path.
 *
 * Disasm (0x37500, 460 bytes):
 *   1. Validate inputs (node != NULL, dotpath != NULL or empty, out_sz > 0)
 *   2. Call HW_CFGTOOL_GetNodeByPath to navigate to target node
 *   3. If found: read value from node (offset 0x24), copy to out buffer
 *   4. If not found: log error via HW_CFGTOOL_SysTrace, return error code
 *
 * @param node    Document handle (from HW_XML_ParseFile)
 * @param dotpath Dot-separated path
 * @param out     Output buffer for value
 * @param out_sz  Size of output buffer
 * @return        0 on success, negative on error
 */
int HW_CFGTOOL_GetXMLValByPath(void *node, const char *dotpath,
                                 char *out, size_t out_sz)
{
    if (!node || !out || out_sz == 0) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x419,
                             "null param %p %p", 0, 0);
        return -1;
    }

    xmlDocPtr doc;
    xmlNodePtr root;

    if (((xmlNodePtr)node)->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr)node;
        root = xmlDocGetRootElement(doc);
    } else {
        root = (xmlNodePtr)node;
    }

    if (!dotpath || !*dotpath) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x419,
                             "null param %p %p", 0, 0);
        return -1;
    }

    /* Resolve path relative to root (strip root element name if present) */
    char pathbuf[512];
    const char *relpath = resolve_root_path(root, dotpath, pathbuf, sizeof(pathbuf));

    xmlNodePtr target;
    if (*relpath == '\0') {
        /* Path is just the root element name */
        target = root;
    } else {
        target = navigate_to_node(root, relpath, 0);
    }

    if (!target) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x420,
                             "node not found for path %s, ret=%d", dotpath, -1);
        return -1;
    }

    /* Read text content – mirrors original which reads node->value at offset 0x24 */
    xmlChar *content = xmlNodeGetContent(target);
    if (!content) {
        out[0] = '\0';
        return 0;
    }
    snprintf(out, out_sz, "%s", (const char *)content);
    xmlFree(content);
    return 0;
}

/*
 * HW_CFGTOOL_SetXMLValByPath  –  set value at dot-path.
 *
 * Disasm (0x37310, 496 bytes):
 *   1. Navigate to target node via GetNodeByPath
 *   2. If found: call HW_XML_SetNodeContent(node, value)
 *   3. If not found: return error
 */
int HW_CFGTOOL_SetXMLValByPath(void *node, const char *dotpath,
                                 const char *value)
{
    if (!node || !dotpath) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x3f0,
                             "null param %p %s", node, dotpath);
        return -1;
    }

    xmlDocPtr doc;
    xmlNodePtr root;

    if (((xmlNodePtr)node)->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr)node;
        root = xmlDocGetRootElement(doc);
    } else {
        root = (xmlNodePtr)node;
    }

    char pathbuf[512];
    const char *relpath = resolve_root_path(root, dotpath, pathbuf, sizeof(pathbuf));

    xmlNodePtr target;
    if (*relpath == '\0') {
        target = root;
    } else {
        target = navigate_to_node(root, relpath, 1);
    }

    if (!target) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x3f8,
                             "node not found for path %s", dotpath);
        return -1;
    }

    xmlNodeSetContent(target, (const xmlChar *)(value ? value : ""));
    return 0;
}

/*
 * HW_CFGTOOL_AddXMLValByPath  –  add node at dot-path.
 *
 * Disasm (0x36ec0, 644 bytes):
 *   The original AddXMLValByPath:
 *   1. SplitPath to get parent_path + leaf_name
 *   2. Navigate to parent via GetNodeByPath
 *   3. Call HW_XML_AddChildNode(parent, new_child) to add under parent
 *   4. If value provided: SetNodeContent on the new child
 */
int HW_CFGTOOL_AddXMLValByPath(void *node, const char *dotpath,
                                 const char *value)
{
    if (!node || !dotpath) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x367,
                             "null param %p %s", node, dotpath);
        return -1;
    }

    xmlDocPtr doc;
    xmlNodePtr root;

    if (((xmlNodePtr)node)->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr)node;
        root = xmlDocGetRootElement(doc);
    } else {
        root = (xmlNodePtr)node;
    }

    /* Split into parent path + leaf name */
    char parent_path[512], leaf_name[256];
    if (split_last_component(dotpath, parent_path, sizeof(parent_path),
                              leaf_name, sizeof(leaf_name)) != 0)
        return -1;

    xmlNodePtr parent;
    if (parent_path[0]) {
        char pathbuf[512];
        const char *relpath = resolve_root_path(root, parent_path,
                                                  pathbuf, sizeof(pathbuf));
        if (*relpath == '\0')
            parent = root;
        else
            parent = navigate_to_node(root, relpath, 1);
    } else {
        parent = root;
    }

    if (!parent) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x370,
                             "parent not found for path %s", dotpath);
        return -1;
    }

    /* AddChildNode – original at 0xa16b0 (188 bytes):
     * Sets new->parent = parent, appends to parent's child list,
     * increments parent->child_count (offset 0x1C) */
    xmlNodePtr child = xmlNewChild(parent, NULL,
                                     (const xmlChar *)leaf_name,
                                     value ? (const xmlChar *)value : NULL);
    return child ? 0 : -1;
}

/*
 * HW_CFGTOOL_DelXMLValByPath  –  delete node at dot-path.
 *
 * Disasm (0x37144, 460 bytes):
 *   1. Navigate to target via GetNodeByPath
 *   2. If found: call HW_XML_FreeSingleNode (unlink + free)
 */
int HW_CFGTOOL_DelXMLValByPath(void *node, const char *dotpath)
{
    if (!node || !dotpath) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x3c5,
                             "null param %p %s", node, dotpath);
        return -1;
    }

    xmlDocPtr doc;
    xmlNodePtr root;

    if (((xmlNodePtr)node)->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr)node;
        root = xmlDocGetRootElement(doc);
    } else {
        root = (xmlNodePtr)node;
    }

    char pathbuf[512];
    const char *relpath = resolve_root_path(root, dotpath, pathbuf, sizeof(pathbuf));

    xmlNodePtr target;
    if (*relpath == '\0') {
        /* Can't delete root */
        return -1;
    }
    target = navigate_to_node(root, relpath, 0);

    if (!target) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x3d0,
                             "node not found for path %s", dotpath);
        return -1;
    }

    /* Original calls HW_XML_FreeSingleNode which calls RemoveAttrNode-style
     * unlinking (0xa1600) then frees the node */
    xmlUnlinkNode(target);
    xmlFreeNode(target);
    return 0;
}

/*
 * HW_CFGTOOL_CloneXMLValByPath  –  clone subtree to destination file.
 *
 * Disasm (0x376cc, 500 bytes):
 *   1. Navigate to source node via GetNodeByPath
 *   2. Call HW_XML_Clone (wrapper at 0xa2108: mov r2,#0; b Clone_Ex)
 *   3. HW_XML_TransformFile to write clone to dst_path
 */
int HW_CFGTOOL_CloneXMLValByPath(void *node, const char *src_dotpath,
                                    const char *dst_path)
{
    if (!node || !src_dotpath || !dst_path) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x440,
                             "null param %p %s %s", node, src_dotpath, dst_path);
        return -1;
    }

    xmlDocPtr doc;
    xmlNodePtr root;

    if (((xmlNodePtr)node)->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr)node;
        root = xmlDocGetRootElement(doc);
    } else {
        root = (xmlNodePtr)node;
    }

    char pathbuf[512];
    const char *relpath = resolve_root_path(root, src_dotpath,
                                              pathbuf, sizeof(pathbuf));
    xmlNodePtr src;
    if (*relpath == '\0')
        src = root;
    else
        src = navigate_to_node(root, relpath, 0);

    if (!src) {
        HW_CFGTOOL_SysTrace("hw_smp_cfg_tool.c", 0x448,
                             "source not found for path %s", src_dotpath);
        return -1;
    }

    /* Deep copy – mirrors HW_XML_Clone at 0xa2108 */
    xmlNodePtr copy = xmlCopyNode(src, 1);
    if (!copy) return -1;

    /* Write clone to destination file */
    xmlDocPtr clone_doc = xmlNewDoc((const xmlChar *)"1.0");
    if (!clone_doc) {
        xmlFreeNode(copy);
        return -1;
    }
    xmlDocSetRootElement(clone_doc, copy);
    int ret = xmlSaveFormatFileEnc(dst_path, clone_doc, "UTF-8", 1);
    xmlFreeDoc(clone_doc);
    return (ret >= 0) ? 0 : -1;
}

/* ======================================================================== */
/*  HW_CFGTOOL_CheckArg  –  decompiled from cfgtool binary @ 0x1de8         */
/*                                                                           */
/*  Original: 440 bytes ARM32.  Validates argc for each operation type.      */
/*                                                                           */
/*  Disasm analysis (V500R022):                                              */
/*    Uses a bitmask: ops needing >= 4 args → mask 0x153 (bits 0,1,4,6,8)   */
/*    ops needing >= 5 args → mask 0xC (bits 2,3)                            */
/*    op 7 (batch) needs argc >= 4                                           */
/* ======================================================================== */
int HW_CFGTOOL_CheckArg(int op_type, int argc, char **argv)
{
    (void)argv;

    if ((unsigned)op_type > 8) return 0;

    /* Bitmask from original: 0x153 = binary 101010011
     * Bits set for: get(1), set(2), create(5), batch(7), gettofile(9) → need >=4 args
     * Plus: find(3), add(4) also handled */
    unsigned mask = 1u << (unsigned)op_type;

    /* Ops: get(1), find(3), del(6), gettofile(9) → need argc >= 4 */
    if (mask & 0x153) {
        /* But set(2), add(4) need argc >= 5 */
        if (mask & 0xC) {
            /* set(2) or add(4): need value → argc >= 5 */
            if (argc < 5) {
                HW_CFGTOOL_SysTrace("hw_cfg_tool.c", 0x1ff,
                                     "argc=%d too small for op %d", argc, op_type);
                return -1;
            }
        }
        return 0;
    }

    /* clone(8) needs argc >= 5 */
    if (op_type == CFGTOOL_OP_CLONE) {
        if (argc < 5) return -1;
        return 0;
    }

    return 0;
}

/* ======================================================================== */
/*  HW_CFGTOOL_GetParaFromString  –  decompiled from cfgtool @ 0x2124       */
/*                                                                           */
/*  Original: 344 bytes ARM32.  Tokenizes a batch line by space/tab.         */
/*  Uses HW_OS_StrtokR internally.                                           */
/* ======================================================================== */
int HW_CFGTOOL_GetParaFromString(const char *line, char **tokens,
                                   int max_tokens, int *count_out)
{
    if (!line || !tokens || !count_out || max_tokens <= 0) return -1;

    char *buf = strdup(line);
    if (!buf) return -1;

    int count = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " \t\r\n", &saveptr);

    while (tok && count < max_tokens) {
        tokens[count] = strdup(tok);
        if (!tokens[count]) {
            for (int i = 0; i < count; i++) free(tokens[i]);
            free(buf);
            return -1;
        }
        count++;
        tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }

    *count_out = count;
    free(buf);
    return 0;
}

/* ======================================================================== */
/*  HW_CFGTOOL_DealBatchType  –  decompiled from cfgtool @ 0x222c           */
/*                                                                           */
/*  Original: 840 bytes ARM32.  Processes batch file line by line.           */
/*  Each line: <op> <dotpath> [value]                                        */
/*  Opens file, reads with HW_OS_Fgets, tokenizes with GetParaFromString,   */
/*  dispatches via GetOptType + direct operation call.                        */
/*  Writes result via BatchChangeRet.                                        */
/* ======================================================================== */

#define BATCH_BUF_SIZE 0x2000  /* 8 KB – matches original stack allocation */
#define BATCH_MAX_TOKENS 10

int HW_CFGTOOL_DealBatchType(void *node, const char *xml_path,
                               const char *batch_file)
{
    FILE *fp;
    char  line[BATCH_BUF_SIZE];
    char *tokens[BATCH_MAX_TOKENS];
    int   token_count;
    int   ret = 0;

    if (!node || !batch_file) return -1;

    fp = HW_OS_Fopen(batch_file, "r");
    if (!fp) {
        HW_CFGTOOL_SysTrace("hw_cfg_tool.c", 0x310,
                             "cannot open batch file %s", batch_file);
        return -1;
    }

    while (HW_OS_Fgets(line, sizeof(line), fp) != NULL) {
        /* Skip empty lines and comments */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;

        memset(tokens, 0, sizeof(tokens));
        token_count = 0;

        if (HW_CFGTOOL_GetParaFromString(p, tokens, BATCH_MAX_TOKENS,
                                          &token_count) != 0 ||
            token_count < 2) {
            for (int i = 0; i < token_count; i++) free(tokens[i]);
            continue;
        }

        /* tokens[0] = operation, tokens[1] = dotpath, tokens[2..] = args */
        int op = HW_CFGTOOL_GetOptType(tokens[0]);
        int line_ret = -1;

        switch (op) {
        case CFGTOOL_OP_GET:
            if (token_count >= 2) {
                char val[256];
                memset(val, 0, sizeof(val));
                line_ret = HW_CFGTOOL_GetXMLValByPath(node, tokens[1],
                                                        val, sizeof(val));
                if (line_ret == 0)
                    HW_OS_Printf("%s\n", val);
            }
            break;

        case CFGTOOL_OP_SET:
            if (token_count >= 3)
                line_ret = HW_CFGTOOL_SetXMLValByPath(node, tokens[1],
                                                        tokens[2]);
            break;

        case CFGTOOL_OP_ADD:
            if (token_count >= 2) {
                const char *val = (token_count >= 3) ? tokens[2] : NULL;
                line_ret = HW_CFGTOOL_AddXMLValByPath(node, tokens[1], val);
            }
            break;

        case CFGTOOL_OP_DEL:
            if (token_count >= 2)
                line_ret = HW_CFGTOOL_DelXMLValByPath(node, tokens[1]);
            break;

        default:
            HW_CFGTOOL_SysTrace("hw_cfg_tool.c", 0x330,
                                 "unknown batch op: %s", tokens[0]);
            break;
        }

        if (line_ret != 0) ret = line_ret;

        for (int i = 0; i < token_count; i++) free(tokens[i]);
    }

    HW_OS_Fclose(fp);
    return ret;
}
