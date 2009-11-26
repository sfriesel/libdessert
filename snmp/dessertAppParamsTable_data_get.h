/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 12088 $ of $
 *
 * $Id:$
 *
 * @file dessertAppParamsTable_data_get.h
 *
 * @addtogroup get
 *
 * Prototypes for get functions
 *
 * @{
 */
#ifndef DESSERTAPPPARAMSTABLE_DATA_GET_H
#define DESSERTAPPPARAMSTABLE_DATA_GET_H

#ifdef __cplusplus
extern          "C" {
#endif

    /*
     *********************************************************************
     * GET function declarations
     */

    /*
     *********************************************************************
     * GET Table declarations
     */
/**********************************************************************
 **********************************************************************
 ***
 *** Table dessertAppParamsTable
 ***
 **********************************************************************
 **********************************************************************/
    /*
     * DESSERT-MIB::dessertAppParamsTable is subid 11 of dessertObjects.
     * Its status is Current.
     * OID: .1.3.6.1.4.1.18898.0.19.10.1.1.11, length: 13
     */
    /*
     * indexes
     */
    int             appParamsIndex_map(long *mib_appParamsIndex_val_ptr,
                                       long raw_appParamsIndex_val);

    int             appParamsName_map(char **mib_appParamsName_val_ptr_ptr,
                                      size_t
                                      *mib_appParamsName_val_ptr_len_ptr,
                                      char *raw_appParamsName_val_ptr,
                                      size_t raw_appParamsName_val_ptr_len,
                                      int allow_realloc);
    int             appParamsName_get(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx,
                                      char **appParamsName_val_ptr_ptr,
                                      size_t
                                      *appParamsName_val_ptr_len_ptr);
    int             appParamsDesc_map(char **mib_appParamsDesc_val_ptr_ptr,
                                      size_t
                                      *mib_appParamsDesc_val_ptr_len_ptr,
                                      char *raw_appParamsDesc_val_ptr,
                                      size_t raw_appParamsDesc_val_ptr_len,
                                      int allow_realloc);
    int             appParamsDesc_get(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx,
                                      char **appParamsDesc_val_ptr_ptr,
                                      size_t
                                      *appParamsDesc_val_ptr_len_ptr);
    int             appParamsValueType_map(u_long *
                                           mib_appParamsValueType_val_ptr,
                                           u_long
                                           raw_appParamsValueType_val);
    int             appParamsValueType_get(dessertAppParamsTable_rowreq_ctx
                                           * rowreq_ctx,
                                           u_long *
                                           appParamsValueType_val_ptr);
    int             appParamsTruthValue_map(u_long *
                                            mib_appParamsTruthValue_val_ptr,
                                            u_long
                                            raw_appParamsTruthValue_val);
    int            
        appParamsTruthValue_get(dessertAppParamsTable_rowreq_ctx *
                                rowreq_ctx,
                                u_long * appParamsTruthValue_val_ptr);
    int             appParamsInteger32_map(long
                                           *mib_appParamsInteger32_val_ptr,
                                           long
                                           raw_appParamsInteger32_val);
    int             appParamsInteger32_get(dessertAppParamsTable_rowreq_ctx
                                           * rowreq_ctx,
                                           long
                                           *appParamsInteger32_val_ptr);
    int             appParamsUnsigned32_map(u_long *
                                            mib_appParamsUnsigned32_val_ptr,
                                            u_long
                                            raw_appParamsUnsigned32_val);
    int            
        appParamsUnsigned32_get(dessertAppParamsTable_rowreq_ctx *
                                rowreq_ctx,
                                u_long * appParamsUnsigned32_val_ptr);
    int             appParamsOctetString_map(char
                                             **mib_appParamsOctetString_val_ptr_ptr,
                                             size_t
                                             *mib_appParamsOctetString_val_ptr_len_ptr,
                                             char
                                             *raw_appParamsOctetString_val_ptr,
                                             size_t
                                             raw_appParamsOctetString_val_ptr_len,
                                             int allow_realloc);
    int            
        appParamsOctetString_get(dessertAppParamsTable_rowreq_ctx *
                                 rowreq_ctx,
                                 char **appParamsOctetString_val_ptr_ptr,
                                 size_t
                                 *appParamsOctetString_val_ptr_len_ptr);


    int            
        dessertAppParamsTable_indexes_set_tbl_idx
        (dessertAppParamsTable_mib_index * tbl_idx,
         long appParamsIndex_val);
    int            
        dessertAppParamsTable_indexes_set(dessertAppParamsTable_rowreq_ctx
                                          * rowreq_ctx,
                                          long appParamsIndex_val);




#ifdef __cplusplus
}
#endif
#endif                          /* DESSERTAPPPARAMSTABLE_DATA_GET_H */
/** @} */
