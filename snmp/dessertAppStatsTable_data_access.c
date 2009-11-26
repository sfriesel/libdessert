/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 14170 $ of $ 
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
#include "dessertAppStatsTable_data_access.h"
#include "../dessert.h"
#include "../dessert_internal.h"

/** @ingroup interface
 * @addtogroup data_access data_access: Routines to access data
 *
 * These routines are used to locate the data used to satisfy
 * requests.
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

/**
 * initialization for dessertAppStatsTable data access
 *
 * This function is called during startup to allow you to
 * allocate any resources you need for the data table.
 *
 * @param dessertAppStatsTable_reg
 *        Pointer to dessertAppStatsTable_registration
 *
 * @retval MFD_SUCCESS : success.
 * @retval MFD_ERROR   : unrecoverable error.
 */
int
dessertAppStatsTable_init_data(dessertAppStatsTable_registration *
                               dessertAppStatsTable_reg)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_init_data", "called\n"));

    /*
     * TODO:303:o: Initialize dessertAppStatsTable data.
     */
    /*
     ***************************************************
     ***             START EXAMPLE CODE              ***
     ***---------------------------------------------***/
    /*
     * if you are the sole writer for the file, you could
     * open it here. However, as stated earlier, we are assuming
     * the worst case, which in this case means that the file is
     * written to by someone else, and might not even exist when
     * we start up. So we can't do anything here.
     */
    /*
     ***---------------------------------------------***
     ***              END  EXAMPLE CODE              ***
     ***************************************************/

    return MFD_SUCCESS;
}                               /* dessertAppStatsTable_init_data */

/**
 * container overview
 *
 */

/**
 * container initialization
 *
 * @param container_ptr_ptr A pointer to a container pointer. If you
 *        create a custom container, use this parameter to return it
 *        to the MFD helper. If set to NULL, the MFD helper will
 *        allocate a container for you.
 * @param  cache A pointer to a cache structure. You can set the timeout
 *         and other cache flags using this pointer.
 *
 *  This function is called at startup to allow you to customize certain
 *  aspects of the access method. For the most part, it is for advanced
 *  users. The default code should suffice for most cases. If no custom
 *  container is allocated, the MFD code will create one for your.
 *
 *  This is also the place to set up cache behavior. The default, to
 *  simply set the cache timeout, will work well with the default
 *  container. If you are using a custom container, you may want to
 *  look at the cache helper documentation to see if there are any
 *  flags you want to set.
 *
 * @remark
 *  This would also be a good place to do any initialization needed
 *  for you data source. For example, opening a connection to another
 *  process that will supply the data, opening a database, etc.
 */
void
dessertAppStatsTable_container_init(netsnmp_container ** container_ptr_ptr,
                                    netsnmp_cache * cache)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_container_init", "called\n"));

    if (NULL == container_ptr_ptr) {
        snmp_log(LOG_ERR,
                 "bad container param to dessertAppStatsTable_container_init\n");
        return;
    }

    /*
     * For advanced users, you can use a custom container. If you
     * do not create one, one will be created for you.
     */
    *container_ptr_ptr = NULL;

    if (NULL == cache) {
        snmp_log(LOG_ERR,
                 "bad cache param to dessertAppStatsTable_container_init\n");
        return;
    }

    /*
     * TODO:345:A: Set up dessertAppStatsTable cache properties.
     *
     * Also for advanced users, you can set parameters for the
     * cache. Do not change the magic pointer, as it is used
     * by the MFD helper. To completely disable caching, set
     * cache->enabled to 0.
     */
    cache->timeout = DESSERTAPPSTATSTABLE_CACHE_TIMEOUT;        /* seconds */
}                               /* dessertAppStatsTable_container_init */

/**
 * container shutdown
 *
 * @param container_ptr A pointer to the container.
 *
 *  This function is called at shutdown to allow you to customize certain
 *  aspects of the access method. For the most part, it is for advanced
 *  users. The default code should suffice for most cases.
 *
 *  This function is called before dessertAppStatsTable_container_free().
 *
 * @remark
 *  This would also be a good place to do any cleanup needed
 *  for you data source. For example, closing a connection to another
 *  process that supplied the data, closing a database, etc.
 */
void
dessertAppStatsTable_container_shutdown(netsnmp_container * container_ptr)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_container_shutdown", "called\n"));

    if (NULL == container_ptr) {
        snmp_log(LOG_ERR,
                 "bad params to dessertAppStatsTable_container_shutdown\n");
        return;
    }

}                               /* dessertAppStatsTable_container_shutdown */

/**
 * load initial data
 *
 * This function will also be called by the cache helper to load
 * the container again (after the container free function has been
 * called to free the previous contents).
 *
 * @param container container to which items should be inserted
 *
 * @retval MFD_SUCCESS              : success.
 * @retval MFD_RESOURCE_UNAVAILABLE : Can't access data source
 * @retval MFD_ERROR                : other error.
 *
 *  This function is called to load the index(es) (and data, optionally)
 *  for the every row in the data set.
 *
 * @remark
 *  While loading the data, the only important thing is the indexes.
 *  If access to your data is cheap/fast (e.g. you have a pointer to a
 *  structure in memory), it would make sense to update the data here.
 *  If, however, the accessing the data invovles more work (e.g. parsing
 *  some other existing data, or peforming calculations to derive the data),
 *  then you can limit yourself to setting the indexes and saving any
 *  information you will need later. Then use the saved information in
 *  dessertAppStatsTable_row_prep() for populating data.
 *
 * @note
 *  If you need consistency between rows (like you want statistics
 *  for each row to be from the same time frame), you should set all
 *  data here.
 *
 */
int dessertAppStatsTable_container_load(netsnmp_container * container) {
	dessertAppStatsTable_rowreq_ctx *rowreq_ctx;
	size_t count = 0;

	dessert_agentx_appstats_t *appstats_list = NULL;
	dessert_agentx_appstats_t *appstat;

	/*
	 * temporary storage for index values
	 */
	long appStatsIndex;

	DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_container_load", "called\n"));
	dessert_debug("dessertAppStatsTable_container_load called");

	/* harvest the appstats from the callbacks registered via *dessert_agentx_appstats_add* */
	if (_dessert_agentx_appstats_harvest_callbacks(&appstats_list)
			== DESSERT_ERR)
		return MFD_RESOURCE_UNAVAILABLE;

	/*
	 * Load/update data in the dessertAppStatsTable container.
	 * loop over your dessertAppStatsTable data, allocate a rowreq context,
	 * set the index(es) [and data, optionally] and insert into
	 * the container.
	 */
	DL_FOREACH(appstats_list, appstat) {

		appStatsIndex = count++;

		/*
		 * set indexes in new dessertAppStatsTable rowreq context.
		 */
		rowreq_ctx = dessertAppStatsTable_allocate_rowreq_ctx();
		if (NULL == rowreq_ctx) {
			snmp_log(LOG_ERR, "memory allocation failed\n");
			return MFD_RESOURCE_UNAVAILABLE;
		}
		if (MFD_SUCCESS != dessertAppStatsTable_indexes_set(rowreq_ctx,
				appStatsIndex)) {
			snmp_log(LOG_ERR, "error setting index while loading "
				"dessertAppStatsTable data.\n");
			dessertAppStatsTable_release_rowreq_ctx(rowreq_ctx);
			continue;
		}

		/* clear all column flags */
		rowreq_ctx->column_exists_flags = 0;

		/* these columns are always present*/
		rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSNAME_FLAG
				| COLUMN_APPSTATSDESC_FLAG | COLUMN_APPSTATSNODEORLINK_FLAG
				| COLUMN_APPSTATSVALUETYPE_FLAG;

		rowreq_ctx->data.appStatsName_len = strlen(appstat->name);
		strcpy(rowreq_ctx->data.appStatsName, appstat->name);

		rowreq_ctx->data.appStatsDesc_len = strlen(appstat->desc);
		strcpy(rowreq_ctx->data.appStatsDesc, appstat->desc);

		appStatsNodeOrLink_map(&(rowreq_ctx->data.appStatsNodeOrLink),appstat->node_or_link);
		appStatsValueType_map(&(rowreq_ctx->data.appStatsValueType),appstat->value_type);

		/* are the macaddress? columns present?*/
		switch (appstat->node_or_link) {

		case DESSERT_APPSTATS_NODEORLINK_NONE:
			break;
		case DESSERT_APPSTATS_NODEORLINK_NODE:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSMACADDRESS1_FLAG;

			rowreq_ctx->data.appStatsMacAddress1_len = ETHER_ADDR_LEN;
			memcpy(rowreq_ctx->data.appStatsMacAddress1, appstat->macaddress1,
					ETHER_ADDR_LEN);

			break;
		case DESSERT_APPSTATS_NODEORLINK_LINK:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSMACADDRESS1_FLAG
					| COLUMN_APPSTATSMACADDRESS2_FLAG;

			rowreq_ctx->data.appStatsMacAddress1_len = ETHER_ADDR_LEN;
			memcpy(rowreq_ctx->data.appStatsMacAddress1, appstat->macaddress1,
					ETHER_ADDR_LEN);

			rowreq_ctx->data.appStatsMacAddress2_len = ETHER_ADDR_LEN;
			memcpy(rowreq_ctx->data.appStatsMacAddress2, appstat->macaddress2,
					ETHER_ADDR_LEN);

			break;
		default:
			dessert_err("appstats->node_or_link not valid!");
		}

		/* which of the 'value'-columns is actually present? */
		switch (appstat->value_type) {

		case DESSERT_APPSTATS_VALUETYPE_BOOL:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSTRUTHVALUE_FLAG;
			appStatsTruthValue_map(&(rowreq_ctx->data.appStatsTruthValue),appstat->bool);
			break;

		case DESSERT_APPSTATS_VALUETYPE_INT32:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSINTEGER32_FLAG;
			rowreq_ctx->data.appStatsInteger32 = appstat->int32;

			break;

		case DESSERT_APPSTATS_VALUETYPE_UINT32:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSUNSIGNED32_FLAG;
			rowreq_ctx->data.appStatsUnsigned32 = appstat->uint32;

			break;

		case DESSERT_APPSTATS_VALUETYPE_COUNTER64:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSCOUNTER64_FLAG;
			rowreq_ctx->data.appStatsCounter64.low = appstat->counter64
					& 0xffffffff;
			rowreq_ctx->data.appStatsCounter64.high = appstat->counter64 >> 32;

			break;

		case DESSERT_APPSTATS_VALUETYPE_OCTETSTRING:
			rowreq_ctx->column_exists_flags |= COLUMN_APPSTATSOCTETSTRING_FLAG;
			rowreq_ctx->data.appStatsOctetString_len = appstat->octetstring_len;
			memcpy(&(rowreq_ctx->data.appStatsOctetString), appstat->octetstring, appstat->octetstring_len);

			break;

		default:
			dessert_err("appstats->value_type not valid! [%s]", appstat->name);
		}

		/*
		 * insert into table container
		 */
		CONTAINER_INSERT(container, rowreq_ctx);
	}

	_dessert_agentx_appstats_free_list(&appstats_list);

	DEBUGMSGT(("verbose:dessertAppStatsTable:dessertAppStatsTable_container_load", "inserted %d records\n", count));

	return MFD_SUCCESS;
} /* dessertAppStatsTable_container_load */

/**
 * container clean up
 *
 * @param container container with all current items
 *
 *  This optional callback is called prior to all
 *  item's being removed from the container. If you
 *  need to do any processing before that, do it here.
 *
 * @note
 *  The MFD helper will take care of releasing all the row contexts.
 *
 */
void
dessertAppStatsTable_container_free(netsnmp_container * container)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_container_free", "called\n"));

    /*
     * TODO:380:M: Free dessertAppStatsTable container data.
     */
}                               /* dessertAppStatsTable_container_free */

/**
 * prepare row for processing.
 *
 *  When the agent has located the row for a request, this function is
 *  called to prepare the row for processing. If you fully populated
 *  the data context during the index setup phase, you may not need to
 *  do anything.
 *
 * @param rowreq_ctx pointer to a context.
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 */
int
dessertAppStatsTable_row_prep(dessertAppStatsTable_rowreq_ctx * rowreq_ctx)
{
    DEBUGMSGTL(("verbose:dessertAppStatsTable:dessertAppStatsTable_row_prep", "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:390:o: Prepare row for request.
     * If populating row data was delayed, this is the place to
     * fill in the row for this request.
     */

    return MFD_SUCCESS;
}                               /* dessertAppStatsTable_row_prep */

/** @} */
