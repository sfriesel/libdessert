/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 12088 $ of $ 
 *
 * $Id:$
 */
/*
 * standard Net-SNMP includes 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 * include our parent header 
 */
#include "dessertAppStatsTable.h"


/** @defgroup data_get data_get: Routines to get data
 *
 * TODO:230:M: Implement dessertAppStatsTable get routines.
 * TODO:240:M: Implement dessertAppStatsTable mapping routines (if any).
 *
 * These routine are used to get the value for individual objects. The
 * row context is passed, along with a pointer to the memory where the
 * value should be copied.
 *
 * @{
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table dessertAppStatsTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * DESSERT-MIB::dessertAppStatsTable is subid 9 of dessertObjects.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9, length: 12
 */

/*
 * ---------------------------------------------------------------------
 * * TODO:200:r: Implement dessertAppStatsTable data context functions.
 */


/**
 * set mib index(es)
 *
 * @param tbl_idx mib index structure
 * @param appStatsIndex_val
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 *
 * @remark
 *  This convenience function is useful for setting all the MIB index
 *  components with a single function call. It is assume that the C values
 *  have already been mapped from their native/rawformat to the MIB format.
 */
int
dessertAppStatsTable_indexes_set_tbl_idx(dessertAppStatsTable_mib_index *
                                         tbl_idx, long appStatsIndex_val)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_indexes_set_tbl_idx", "called\n"));

    /*
     * appStatsIndex(1)///()//L/a/w/e/r/d/h 
     */
    tbl_idx->appStatsIndex = appStatsIndex_val;


    return MFD_SUCCESS;
}                               /* dessertAppStatsTable_indexes_set_tbl_idx */

/**
 * @internal
 * set row context indexes
 *
 * @param reqreq_ctx the row context that needs updated indexes
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 *
 * @remark
 *  This function sets the mib indexs, then updates the oid indexs
 *  from the mib index.
 */
int
dessertAppStatsTable_indexes_set(dessertAppStatsTable_rowreq_ctx *
                                 rowreq_ctx, long appStatsIndex_val)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_indexes_set", "called\n"));

    if (MFD_SUCCESS !=
        dessertAppStatsTable_indexes_set_tbl_idx(&rowreq_ctx->tbl_idx,
                                                 appStatsIndex_val))
        return MFD_ERROR;

    /*
     * convert mib index to oid index
     */
    rowreq_ctx->oid_idx.len = sizeof(rowreq_ctx->oid_tmp) / sizeof(oid);
    if (0 != dessertAppStatsTable_index_to_oid(&rowreq_ctx->oid_idx,
                                               &rowreq_ctx->tbl_idx)) {
        return MFD_ERROR;
    }

    return MFD_SUCCESS;
}                               /* dessertAppStatsTable_indexes_set */


/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsName
 * appStatsName is subid 2 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.2
 * Description:
The name of the statistical datum
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 255a
 *
 * Ranges:  0 - 255;
 *
 * Its syntax is DisplayString (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 255)
 */
/**
 * Extract the current value of the appStatsName data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsName_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param appStatsName_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by appStatsName.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*appStatsName_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update appStatsName_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
appStatsName_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                 char **appStatsName_val_ptr_ptr,
                 size_t *appStatsName_val_ptr_len_ptr)
{
   /** we should have a non-NULL pointer and enough storage */
    netsnmp_assert((NULL != appStatsName_val_ptr_ptr)
                   && (NULL != *appStatsName_val_ptr_ptr));
    netsnmp_assert(NULL != appStatsName_val_ptr_len_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsName_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsName data.
     * copy (* appStatsName_val_ptr_ptr ) data and (* appStatsName_val_ptr_len_ptr ) from rowreq_ctx->data
     */
    /*
     * make sure there is enough space for appStatsName data
     */
    if ((NULL == (*appStatsName_val_ptr_ptr)) ||
        ((*appStatsName_val_ptr_len_ptr) <
         (rowreq_ctx->data.appStatsName_len *
          sizeof(rowreq_ctx->data.appStatsName[0])))) {
        /*
         * allocate space for appStatsName data
         */
        (*appStatsName_val_ptr_ptr) =
            malloc(rowreq_ctx->data.appStatsName_len *
                   sizeof(rowreq_ctx->data.appStatsName[0]));
        if (NULL == (*appStatsName_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory\n");
            return MFD_ERROR;
        }
    }
    (*appStatsName_val_ptr_len_ptr) =
        rowreq_ctx->data.appStatsName_len *
        sizeof(rowreq_ctx->data.appStatsName[0]);
    memcpy((*appStatsName_val_ptr_ptr), rowreq_ctx->data.appStatsName,
           rowreq_ctx->data.appStatsName_len *
           sizeof(rowreq_ctx->data.appStatsName[0]));

    return MFD_SUCCESS;
}                               /* appStatsName_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsDesc
 * appStatsDesc is subid 3 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.3
 * Description:
A short description of the statistical datum
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 255a
 *
 * Ranges:  0 - 255;
 *
 * Its syntax is DisplayString (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 255)
 */
/**
 * Extract the current value of the appStatsDesc data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsDesc_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param appStatsDesc_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by appStatsDesc.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*appStatsDesc_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update appStatsDesc_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
appStatsDesc_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                 char **appStatsDesc_val_ptr_ptr,
                 size_t *appStatsDesc_val_ptr_len_ptr)
{
   /** we should have a non-NULL pointer and enough storage */
    netsnmp_assert((NULL != appStatsDesc_val_ptr_ptr)
                   && (NULL != *appStatsDesc_val_ptr_ptr));
    netsnmp_assert(NULL != appStatsDesc_val_ptr_len_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsDesc_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsDesc data.
     * copy (* appStatsDesc_val_ptr_ptr ) data and (* appStatsDesc_val_ptr_len_ptr ) from rowreq_ctx->data
     */
    /*
     * make sure there is enough space for appStatsDesc data
     */
    if ((NULL == (*appStatsDesc_val_ptr_ptr)) ||
        ((*appStatsDesc_val_ptr_len_ptr) <
         (rowreq_ctx->data.appStatsDesc_len *
          sizeof(rowreq_ctx->data.appStatsDesc[0])))) {
        /*
         * allocate space for appStatsDesc data
         */
        (*appStatsDesc_val_ptr_ptr) =
            malloc(rowreq_ctx->data.appStatsDesc_len *
                   sizeof(rowreq_ctx->data.appStatsDesc[0]));
        if (NULL == (*appStatsDesc_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory\n");
            return MFD_ERROR;
        }
    }
    (*appStatsDesc_val_ptr_len_ptr) =
        rowreq_ctx->data.appStatsDesc_len *
        sizeof(rowreq_ctx->data.appStatsDesc[0]);
    memcpy((*appStatsDesc_val_ptr_ptr), rowreq_ctx->data.appStatsDesc,
           rowreq_ctx->data.appStatsDesc_len *
           sizeof(rowreq_ctx->data.appStatsDesc[0]));

    return MFD_SUCCESS;
}                               /* appStatsDesc_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsNodeOrLink
 * appStatsNodeOrLink is subid 4 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.4
 * Description:
Determines which of the appStatsMacAddress{1,2} coloumns
        is valid and therefore indicates whether the information provided
        by this row relates to a node or a link. 
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  1      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 * Enum range: 3/8. Values:  none(0), node(1), link(2)
 *
 * Its syntax is INTEGER (based on perltype INTEGER)
 * The net-snmp type is ASN_INTEGER. The C type decl is long (u_long)
 */
/**
 * map a value from its original native format to the MIB format.
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_ERROR           : Any other error
 *
 * @note parameters follow the memset convention (dest, src).
 *
 * @note generation and use of this function can be turned off by re-running
 * mib2c after adding the following line to the file
 * defaults/node-appStatsNodeOrLink.m2d :
 *   @eval $m2c_node_skip_mapping = 1@
 *
 * @remark
 *  If the values for your data type don't exactly match the
 *  possible values defined by the mib, you should map them here.
 *  Otherwise, just do a direct copy.
 */
int
appStatsNodeOrLink_map(u_long * mib_appStatsNodeOrLink_val_ptr,
                       u_long raw_appStatsNodeOrLink_val)
{
    netsnmp_assert(NULL != mib_appStatsNodeOrLink_val_ptr);

    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsNodeOrLink_map",
                "called\n"));

    /*
     * TODO:241:o: |-> Implement appStatsNodeOrLink enum mapping.
     * uses INTERNAL_* macros defined in the header files
     */
    switch (raw_appStatsNodeOrLink_val) {
    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSNODEORLINK_NONE:
        *mib_appStatsNodeOrLink_val_ptr = APPSTATSNODEORLINK_NONE;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSNODEORLINK_NODE:
        *mib_appStatsNodeOrLink_val_ptr = APPSTATSNODEORLINK_NODE;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSNODEORLINK_LINK:
        *mib_appStatsNodeOrLink_val_ptr = APPSTATSNODEORLINK_LINK;
        break;

    default:
        snmp_log(LOG_ERR,
                 "couldn't map value %ld for appStatsNodeOrLink\n",
                 raw_appStatsNodeOrLink_val);
        return MFD_ERROR;
    }

    return MFD_SUCCESS;
}                               /* appStatsNodeOrLink_map */

/**
 * Extract the current value of the appStatsNodeOrLink data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsNodeOrLink_val_ptr
 *        Pointer to storage for a long variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
appStatsNodeOrLink_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                       u_long * appStatsNodeOrLink_val_ptr)
{
   /** we should have a non-NULL pointer */
    netsnmp_assert(NULL != appStatsNodeOrLink_val_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsNodeOrLink_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsNodeOrLink data.
     * copy (* appStatsNodeOrLink_val_ptr ) from rowreq_ctx->data
     */
    (*appStatsNodeOrLink_val_ptr) = rowreq_ctx->data.appStatsNodeOrLink;

    return MFD_SUCCESS;
}                               /* appStatsNodeOrLink_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsValueType
 * appStatsValueType is subid 5 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.5
 * Description:
Indicates which of the coloumns (appStatsTruthValue, 
        appStatsInterger32, appStatsUInteger32, appStatsCounter64, 
        appStatsOctetString) in the dessertAppStatsTable is actually valid.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  1      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 * Enum range: 3/8. Values:  bool(0), int32(1), uint32(2), counter64(3), octetstring(4)
 *
 * Its syntax is INTEGER (based on perltype INTEGER)
 * The net-snmp type is ASN_INTEGER. The C type decl is long (u_long)
 */
/**
 * map a value from its original native format to the MIB format.
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_ERROR           : Any other error
 *
 * @note parameters follow the memset convention (dest, src).
 *
 * @note generation and use of this function can be turned off by re-running
 * mib2c after adding the following line to the file
 * defaults/node-appStatsValueType.m2d :
 *   @eval $m2c_node_skip_mapping = 1@
 *
 * @remark
 *  If the values for your data type don't exactly match the
 *  possible values defined by the mib, you should map them here.
 *  Otherwise, just do a direct copy.
 */
int
appStatsValueType_map(u_long * mib_appStatsValueType_val_ptr,
                      u_long raw_appStatsValueType_val)
{
    netsnmp_assert(NULL != mib_appStatsValueType_val_ptr);

    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsValueType_map",
                "called\n"));

    /*
     * TODO:241:o: |-> Implement appStatsValueType enum mapping.
     * uses INTERNAL_* macros defined in the header files
     */
    switch (raw_appStatsValueType_val) {
    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSVALUETYPE_BOOL:
        *mib_appStatsValueType_val_ptr = APPSTATSVALUETYPE_BOOL;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSVALUETYPE_INT32:
        *mib_appStatsValueType_val_ptr = APPSTATSVALUETYPE_INT32;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSVALUETYPE_UINT32:
        *mib_appStatsValueType_val_ptr = APPSTATSVALUETYPE_UINT32;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSVALUETYPE_COUNTER64:
        *mib_appStatsValueType_val_ptr = APPSTATSVALUETYPE_COUNTER64;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSVALUETYPE_OCTETSTRING:
        *mib_appStatsValueType_val_ptr = APPSTATSVALUETYPE_OCTETSTRING;
        break;

    default:
        snmp_log(LOG_ERR, "couldn't map value %ld for appStatsValueType\n",
                 raw_appStatsValueType_val);
        return MFD_ERROR;
    }

    return MFD_SUCCESS;
}                               /* appStatsValueType_map */

/**
 * Extract the current value of the appStatsValueType data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsValueType_val_ptr
 *        Pointer to storage for a long variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
appStatsValueType_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                      u_long * appStatsValueType_val_ptr)
{
   /** we should have a non-NULL pointer */
    netsnmp_assert(NULL != appStatsValueType_val_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsValueType_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsValueType data.
     * copy (* appStatsValueType_val_ptr ) from rowreq_ctx->data
     */
    (*appStatsValueType_val_ptr) = rowreq_ctx->data.appStatsValueType;

    return MFD_SUCCESS;
}                               /* appStatsValueType_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsMacAddress1
 * appStatsMacAddress1 is subid 6 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.6
 * Description:
The hardware address of a node.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 1x:
 *
 * Ranges:  6;
 *
 * Its syntax is MacAddress (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 6)
 */
/**
 * Extract the current value of the appStatsMacAddress1 data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsMacAddress1_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param appStatsMacAddress1_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by appStatsMacAddress1.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*appStatsMacAddress1_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update appStatsMacAddress1_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
appStatsMacAddress1_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                        char **appStatsMacAddress1_val_ptr_ptr,
                        size_t *appStatsMacAddress1_val_ptr_len_ptr)
{
   /** we should have a non-NULL pointer and enough storage */
    netsnmp_assert((NULL != appStatsMacAddress1_val_ptr_ptr)
                   && (NULL != *appStatsMacAddress1_val_ptr_ptr));
    netsnmp_assert(NULL != appStatsMacAddress1_val_ptr_len_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsMacAddress1_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsMacAddress1 data.
     * copy (* appStatsMacAddress1_val_ptr_ptr ) data and (* appStatsMacAddress1_val_ptr_len_ptr ) from rowreq_ctx->data
     */
    /*
     * make sure there is enough space for appStatsMacAddress1 data
     */
    if ((NULL == (*appStatsMacAddress1_val_ptr_ptr)) ||
        ((*appStatsMacAddress1_val_ptr_len_ptr) <
         (rowreq_ctx->data.appStatsMacAddress1_len *
          sizeof(rowreq_ctx->data.appStatsMacAddress1[0])))) {
        /*
         * allocate space for appStatsMacAddress1 data
         */
        (*appStatsMacAddress1_val_ptr_ptr) =
            malloc(rowreq_ctx->data.appStatsMacAddress1_len *
                   sizeof(rowreq_ctx->data.appStatsMacAddress1[0]));
        if (NULL == (*appStatsMacAddress1_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory\n");
            return MFD_ERROR;
        }
    }
    (*appStatsMacAddress1_val_ptr_len_ptr) =
        rowreq_ctx->data.appStatsMacAddress1_len *
        sizeof(rowreq_ctx->data.appStatsMacAddress1[0]);
    memcpy((*appStatsMacAddress1_val_ptr_ptr),
           rowreq_ctx->data.appStatsMacAddress1,
           rowreq_ctx->data.appStatsMacAddress1_len *
           sizeof(rowreq_ctx->data.appStatsMacAddress1[0]));

    return MFD_SUCCESS;
}                               /* appStatsMacAddress1_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsMacAddress2
 * appStatsMacAddress2 is subid 7 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.7
 * Description:
The hardware address of a second node.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 1x:
 *
 * Ranges:  6;
 *
 * Its syntax is MacAddress (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 6)
 */
/**
 * Extract the current value of the appStatsMacAddress2 data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsMacAddress2_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param appStatsMacAddress2_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by appStatsMacAddress2.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*appStatsMacAddress2_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update appStatsMacAddress2_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
appStatsMacAddress2_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                        char **appStatsMacAddress2_val_ptr_ptr,
                        size_t *appStatsMacAddress2_val_ptr_len_ptr)
{
   /** we should have a non-NULL pointer and enough storage */
    netsnmp_assert((NULL != appStatsMacAddress2_val_ptr_ptr)
                   && (NULL != *appStatsMacAddress2_val_ptr_ptr));
    netsnmp_assert(NULL != appStatsMacAddress2_val_ptr_len_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsMacAddress2_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsMacAddress2 data.
     * copy (* appStatsMacAddress2_val_ptr_ptr ) data and (* appStatsMacAddress2_val_ptr_len_ptr ) from rowreq_ctx->data
     */
    /*
     * make sure there is enough space for appStatsMacAddress2 data
     */
    if ((NULL == (*appStatsMacAddress2_val_ptr_ptr)) ||
        ((*appStatsMacAddress2_val_ptr_len_ptr) <
         (rowreq_ctx->data.appStatsMacAddress2_len *
          sizeof(rowreq_ctx->data.appStatsMacAddress2[0])))) {
        /*
         * allocate space for appStatsMacAddress2 data
         */
        (*appStatsMacAddress2_val_ptr_ptr) =
            malloc(rowreq_ctx->data.appStatsMacAddress2_len *
                   sizeof(rowreq_ctx->data.appStatsMacAddress2[0]));
        if (NULL == (*appStatsMacAddress2_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory\n");
            return MFD_ERROR;
        }
    }
    (*appStatsMacAddress2_val_ptr_len_ptr) =
        rowreq_ctx->data.appStatsMacAddress2_len *
        sizeof(rowreq_ctx->data.appStatsMacAddress2[0]);
    memcpy((*appStatsMacAddress2_val_ptr_ptr),
           rowreq_ctx->data.appStatsMacAddress2,
           rowreq_ctx->data.appStatsMacAddress2_len *
           sizeof(rowreq_ctx->data.appStatsMacAddress2[0]));

    return MFD_SUCCESS;
}                               /* appStatsMacAddress2_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsTruthValue
 * appStatsTruthValue is subid 8 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.8
 * Description:
A statistical datum with TruthValue semantics.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  1      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 * Enum range: 2/8. Values:  true(1), false(2)
 *
 * Its syntax is TruthValue (based on perltype INTEGER)
 * The net-snmp type is ASN_INTEGER. The C type decl is long (u_long)
 */
/**
 * map a value from its original native format to the MIB format.
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_ERROR           : Any other error
 *
 * @note parameters follow the memset convention (dest, src).
 *
 * @note generation and use of this function can be turned off by re-running
 * mib2c after adding the following line to the file
 * defaults/node-appStatsTruthValue.m2d :
 *   @eval $m2c_node_skip_mapping = 1@
 *
 * @remark
 *  If the values for your data type don't exactly match the
 *  possible values defined by the mib, you should map them here.
 *  Otherwise, just do a direct copy.
 */
int
appStatsTruthValue_map(u_long * mib_appStatsTruthValue_val_ptr,
                       u_long raw_appStatsTruthValue_val)
{
    netsnmp_assert(NULL != mib_appStatsTruthValue_val_ptr);

    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsTruthValue_map",
                "called\n"));

    /*
     * TODO:241:o: |-> Implement appStatsTruthValue enum mapping.
     * uses INTERNAL_* macros defined in the header files
     */
    switch (raw_appStatsTruthValue_val) {
    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSTRUTHVALUE_TRUE:
        *mib_appStatsTruthValue_val_ptr = TRUTHVALUE_TRUE;
        break;

    case INTERNAL_DESSERTAPPSTATSTABLE_APPSTATSTRUTHVALUE_FALSE:
        *mib_appStatsTruthValue_val_ptr = TRUTHVALUE_FALSE;
        break;

    default:
        snmp_log(LOG_ERR,
                 "couldn't map value %ld for appStatsTruthValue\n",
                 raw_appStatsTruthValue_val);
        return MFD_ERROR;
    }

    return MFD_SUCCESS;
}                               /* appStatsTruthValue_map */

/**
 * Extract the current value of the appStatsTruthValue data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsTruthValue_val_ptr
 *        Pointer to storage for a long variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
appStatsTruthValue_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                       u_long * appStatsTruthValue_val_ptr)
{
   /** we should have a non-NULL pointer */
    netsnmp_assert(NULL != appStatsTruthValue_val_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsTruthValue_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsTruthValue data.
     * copy (* appStatsTruthValue_val_ptr ) from rowreq_ctx->data
     */
    (*appStatsTruthValue_val_ptr) = rowreq_ctx->data.appStatsTruthValue;

    return MFD_SUCCESS;
}                               /* appStatsTruthValue_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsInteger32
 * appStatsInteger32 is subid 9 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.9
 * Description:
A statistical datum with Integer32 semantics.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 *
 * Its syntax is INTEGER32 (based on perltype INTEGER32)
 * The net-snmp type is ASN_INTEGER. The C type decl is long (long)
 */
/**
 * Extract the current value of the appStatsInteger32 data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsInteger32_val_ptr
 *        Pointer to storage for a long variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
appStatsInteger32_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                      long *appStatsInteger32_val_ptr)
{
   /** we should have a non-NULL pointer */
    netsnmp_assert(NULL != appStatsInteger32_val_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsInteger32_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsInteger32 data.
     * copy (* appStatsInteger32_val_ptr ) from rowreq_ctx->data
     */
    (*appStatsInteger32_val_ptr) = rowreq_ctx->data.appStatsInteger32;

    return MFD_SUCCESS;
}                               /* appStatsInteger32_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsUnsigned32
 * appStatsUnsigned32 is subid 10 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.10
 * Description:
A statistical datum with Unsigned32 semantics.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 *
 * Its syntax is UNSIGNED32 (based on perltype UNSIGNED32)
 * The net-snmp type is ASN_UNSIGNED. The C type decl is u_long (u_long)
 */
/**
 * Extract the current value of the appStatsUnsigned32 data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsUnsigned32_val_ptr
 *        Pointer to storage for a u_long variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
appStatsUnsigned32_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                       u_long * appStatsUnsigned32_val_ptr)
{
   /** we should have a non-NULL pointer */
    netsnmp_assert(NULL != appStatsUnsigned32_val_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsUnsigned32_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsUnsigned32 data.
     * copy (* appStatsUnsigned32_val_ptr ) from rowreq_ctx->data
     */
    (*appStatsUnsigned32_val_ptr) = rowreq_ctx->data.appStatsUnsigned32;

    return MFD_SUCCESS;
}                               /* appStatsUnsigned32_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsCounter64
 * appStatsCounter64 is subid 11 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.11
 * Description:
A statistical datum with Counter64 semantics.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 *
 * Its syntax is COUNTER64 (based on perltype COUNTER64)
 * The net-snmp type is ASN_COUNTER64. The C type decl is U64 (U64)
 */
/**
 * Extract the current value of the appStatsCounter64 data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsCounter64_val_ptr
 *        Pointer to storage for a U64 variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
appStatsCounter64_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                      U64 * appStatsCounter64_val_ptr)
{
   /** we should have a non-NULL pointer */
    netsnmp_assert(NULL != appStatsCounter64_val_ptr);

    /*
     * TODO:231:o: |-> copy appStatsCounter64 data.
     * get (* appStatsCounter64_val_ptr ).low and (* appStatsCounter64_val_ptr ).high from rowreq_ctx->data
     */
    (*appStatsCounter64_val_ptr).high =
        rowreq_ctx->data.appStatsCounter64.high;
    (*appStatsCounter64_val_ptr).low =
        rowreq_ctx->data.appStatsCounter64.low;


    return MFD_SUCCESS;
}                               /* appStatsCounter64_get */

/*---------------------------------------------------------------------
 * DESSERT-MIB::dessertAppStatsEntry.appStatsOctetString
 * appStatsOctetString is subid 12 of dessertAppStatsEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.18898.0.19.42.1.9.1.12
 * Description:
A statistical datum containing of up to 1024 octets.
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   0
 *   settable   0
 *
 * Ranges:  0 - 1024;
 *
 * Its syntax is OCTETSTR (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 1024)
 */
/**
 * Extract the current value of the appStatsOctetString data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param appStatsOctetString_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param appStatsOctetString_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by appStatsOctetString.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*appStatsOctetString_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update appStatsOctetString_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
appStatsOctetString_get(dessertAppStatsTable_rowreq_ctx * rowreq_ctx,
                        char **appStatsOctetString_val_ptr_ptr,
                        size_t *appStatsOctetString_val_ptr_len_ptr)
{
   /** we should have a non-NULL pointer and enough storage */
    netsnmp_assert((NULL != appStatsOctetString_val_ptr_ptr)
                   && (NULL != *appStatsOctetString_val_ptr_ptr));
    netsnmp_assert(NULL != appStatsOctetString_val_ptr_len_ptr);


    DEBUGMSGTL(("verbose:dessertAppStatsTable:appStatsOctetString_get",
                "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:231:o: |-> Extract the current value of the appStatsOctetString data.
     * copy (* appStatsOctetString_val_ptr_ptr ) data and (* appStatsOctetString_val_ptr_len_ptr ) from rowreq_ctx->data
     */
    /*
     * make sure there is enough space for appStatsOctetString data
     */
    if ((NULL == (*appStatsOctetString_val_ptr_ptr)) ||
        ((*appStatsOctetString_val_ptr_len_ptr) <
         (rowreq_ctx->data.appStatsOctetString_len *
          sizeof(rowreq_ctx->data.appStatsOctetString[0])))) {
        /*
         * allocate space for appStatsOctetString data
         */
        (*appStatsOctetString_val_ptr_ptr) =
            malloc(rowreq_ctx->data.appStatsOctetString_len *
                   sizeof(rowreq_ctx->data.appStatsOctetString[0]));
        if (NULL == (*appStatsOctetString_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory\n");
            return MFD_ERROR;
        }
    }
    (*appStatsOctetString_val_ptr_len_ptr) =
        rowreq_ctx->data.appStatsOctetString_len *
        sizeof(rowreq_ctx->data.appStatsOctetString[0]);
    memcpy((*appStatsOctetString_val_ptr_ptr),
           rowreq_ctx->data.appStatsOctetString,
           rowreq_ctx->data.appStatsOctetString_len *
           sizeof(rowreq_ctx->data.appStatsOctetString[0]));

    return MFD_SUCCESS;
}                               /* appStatsOctetString_get */



/** @} */