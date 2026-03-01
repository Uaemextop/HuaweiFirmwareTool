/*
 * cfgtool_xml.h  –  Standalone XML engine for cfgtool (decompiled)
 *
 * Provides real implementations of HW_XML_* and HW_CFGTOOL_*XMLValByPath
 * functions using libxml2, replacing the stubs in hw_os_stubs.c.
 *
 * Decompiled from:
 *   - libhw_ssp_basic.so → HW_XML_ParseFile, FreeNode, NewNode, etc.
 *   - libsmp_api.so → HW_CFGTOOL_GetXMLValByPath, Set, Add, Del, Clone
 *   - cfgtool binary → CheckArg, GetParaFromString, DealBatchType
 */
#ifndef CFGTOOL_XML_H
#define CFGTOOL_XML_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── XML document operations (from libhw_ssp_basic.so) ───────────────────── */
void *HW_XML_ParseFile(const char *path, void **node_out);
void  HW_XML_FreeNode(void *node);
void  HW_XML_FreeSingleNode(void *node);
void *HW_XML_NewNode(const char *name);
int   HW_XML_SetNodeContent(void *node, const char *content);
int   HW_XML_TransformFile(void *node, const char *path);

/* ── cfgtool path-based operations (from libsmp_api.so) ──────────────────── */
int   HW_CFGTOOL_GetXMLValByPath(void *node, const char *dotpath,
                                   char *out, size_t out_sz);
int   HW_CFGTOOL_SetXMLValByPath(void *node, const char *dotpath,
                                   const char *value);
int   HW_CFGTOOL_AddXMLValByPath(void *node, const char *dotpath,
                                   const char *value);
int   HW_CFGTOOL_DelXMLValByPath(void *node, const char *dotpath);
int   HW_CFGTOOL_CloneXMLValByPath(void *node, const char *dotpath,
                                      const char *dst_path);

/* ── Argument and batch processing (from cfgtool binary) ─────────────────── */
int   HW_CFGTOOL_CheckArg(int op_type, int argc, char **argv);
int   HW_CFGTOOL_GetParaFromString(const char *line, char **tokens,
                                     int max_tokens, int *count_out);
int   HW_CFGTOOL_DealBatchType(void *node, const char *xml_path,
                                 const char *batch_file);

#ifdef __cplusplus
}
#endif

#endif /* CFGTOOL_XML_H */
