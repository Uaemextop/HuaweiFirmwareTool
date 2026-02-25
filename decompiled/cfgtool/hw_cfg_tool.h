/*
 * hw_cfg_tool.h  –  Huawei cfgtool API (reconstructed)
 */

#ifndef HW_CFG_TOOL_H
#define HW_CFG_TOOL_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Operation types ────────────────────────────────────────────────────── */
typedef enum {
    CFGTOOL_OP_NONE      = 0,
    CFGTOOL_OP_GET       = 1,
    CFGTOOL_OP_SET       = 2,
    CFGTOOL_OP_FIND      = 3,
    CFGTOOL_OP_ADD       = 4,
    CFGTOOL_OP_CREATE    = 5,
    CFGTOOL_OP_DEL       = 6,
    CFGTOOL_OP_BATCH     = 7,
    CFGTOOL_OP_CLONE     = 8,
    CFGTOOL_OP_GETTOFILE = 9,
} CfgtoolOpType;

/* ── API ─────────────────────────────────────────────────────────────────── */
void  HW_CFGTOOL_ShowUsage(void);
void  HW_CFGTOOL_BatchChangeRet(const char *result_str);
int   HW_CFGTOOL_GetOptFile(char *out, const char *argv2);
int   HW_CFGTOOL_GetOptType(const char *op_str);
void *HW_CFGTOOL_XmlCreate(const char *xml_path, const char *root_name);
int   HW_CFGTOOL_XmlGet(const char *xml_path, const char *xpath);
int   HW_CFGTOOL_XmlFind(const char *xml_path, const char *xpath,
                           const char *pattern);
int   HW_CFGTOOL_XmlGetToFile(const char *xml_path, const char *xpath,
                                const char *out_file);
void  HW_CFGTOOL_FreeArgs(char **argv_out, int *argc_out);
int   HW_CFGTOOL_MallocArgs(uint32_t max_args, int *argc_out, char ***argv_out);
int   HW_CFGTOOL_OperByType(int op_type, void *node,
                              const char *xml_path, const char *xml_opt,
                              int arg_count, char **args, const char *extra_buf);
int   HW_CFGTOOL_GetParaFromString(const char *line, char **tokens,
                                     int max_tokens, int *count_out);
int   HW_CFGTOOL_DealBatchType(void *node, const char *xml_path,
                                 const char *batch_file);

/* Extern imports satisfied by libcfg_api.so */
extern int   HW_CFGTOOL_SetXMLValByPath(void *node, const char *xpath,
                                          const char *value);
extern int   HW_CFGTOOL_AddXMLValByPath(void *node, const char *xpath,
                                          const char *value);
extern int   HW_CFGTOOL_DelXMLValByPath(void *node, const char *xpath);
extern int   HW_CFGTOOL_CloneXMLValByPath(void *node, const char *xpath,
                                             const char *dst_xpath);

#ifdef __cplusplus
}
#endif

#endif /* HW_CFG_TOOL_H */
