/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 14170 $ of $ 
 *
 * $Id:$
 */
/** \page MFD helper for dessertAppParamsTable
 *
 * \section intro Introduction
 * Introductory text.
 *
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
#include "dessertAppParamsTable.h"

#include <net-snmp/agent/mib_modules.h>

#include "dessertAppParamsTable_interface.h"

oid             dessertAppParamsTable_oid[] =
    { DESSERTAPPPARAMSTABLE_OID };
int             dessertAppParamsTable_oid_size =
OID_LENGTH(dessertAppParamsTable_oid);

dessertAppParamsTable_registration dessertAppParamsTable_user_context;

void            initialize_table_dessertAppParamsTable(void);
void            shutdown_table_dessertAppParamsTable(void);


/**
 * Initializes the dessertAppParamsTable module
 */
void
init_dessertAppParamsTable(void)
{
    DEBUGMSGTL(("verbose:dessertAppParamsTable:init_dessertAppParamsTable",
                "called\n"));

    /*
     * TODO:300:o: Perform dessertAppParamsTable one-time module initialization.
     */

    /*
     * here we initialize all the tables we're planning on supporting
     */
    if (should_init("dessertAppParamsTable"))
        initialize_table_dessertAppParamsTable();

}                               /* init_dessertAppParamsTable */

/**
 * Shut-down the dessertAppParamsTable module (agent is exiting)
 */
void
shutdown_dessertAppParamsTable(void)
{
    if (should_init("dessertAppParamsTable"))
        shutdown_table_dessertAppParamsTable();

}

/**
 * Initialize the table dessertAppParamsTable 
 *    (Define its contents and how it's structured)
 */
void
initialize_table_dessertAppParamsTable(void)
{
    dessertAppParamsTable_registration *user_context;
    u_long          flags;

    DEBUGMSGTL(("verbose:dessertAppParamsTable:initialize_table_dessertAppParamsTable", "called\n"));

    /*
     * TODO:301:o: Perform dessertAppParamsTable one-time table initialization.
     */

    /*
     * TODO:302:o: |->Initialize dessertAppParamsTable user context
     * if you'd like to pass in a pointer to some data for this
     * table, allocate or set it up here.
     */
    /*
     * a netsnmp_data_list is a simple way to store void pointers. A simple
     * string token is used to add, find or remove pointers.
     */
    user_context =
        netsnmp_create_data_list("dessertAppParamsTable", NULL, NULL);

    /*
     * No support for any flags yet, but in the future you would
     * set any flags here.
     */
    flags = 0;

    /*
     * call interface initialization code
     */
    _dessertAppParamsTable_initialize_interface(user_context, flags);
}                               /* initialize_table_dessertAppParamsTable */

/**
 * Shutdown the table dessertAppParamsTable 
 */
void
shutdown_table_dessertAppParamsTable(void)
{
    /*
     * call interface shutdown code
     */
    _dessertAppParamsTable_shutdown_interface
        (&dessertAppParamsTable_user_context);
}

/**
 * extra context initialization (eg default values)
 *
 * @param rowreq_ctx    : row request context
 * @param user_init_ctx : void pointer for user (parameter to rowreq_ctx_allocate)
 *
 * @retval MFD_SUCCESS  : no errors
 * @retval MFD_ERROR    : error (context allocate will fail)
 */
int
dessertAppParamsTable_rowreq_ctx_init(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx, void *user_init_ctx)
{
    DEBUGMSGTL(("verbose:dessertAppParamsTable:dessertAppParamsTable_rowreq_ctx_init", "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:210:o: |-> Perform extra dessertAppParamsTable rowreq initialization. (eg DEFVALS)
     */

    return MFD_SUCCESS;
}                               /* dessertAppParamsTable_rowreq_ctx_init */

/**
 * extra context cleanup
 *
 */
void
dessertAppParamsTable_rowreq_ctx_cleanup(dessertAppParamsTable_rowreq_ctx *
                                         rowreq_ctx)
{
    DEBUGMSGTL(("verbose:dessertAppParamsTable:dessertAppParamsTable_rowreq_ctx_cleanup", "called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:211:o: |-> Perform extra dessertAppParamsTable rowreq cleanup.
     */
}                               /* dessertAppParamsTable_rowreq_ctx_cleanup */

/**
 * pre-request callback
 *
 *
 * @retval MFD_SUCCESS              : success.
 * @retval MFD_ERROR                : other error
 */
int
dessertAppParamsTable_pre_request(dessertAppParamsTable_registration *
                                  user_context)
{
    DEBUGMSGTL(("verbose:dessertAppParamsTable:dessertAppParamsTable_pre_request", "called\n"));

    /*
     * TODO:510:o: Perform dessertAppParamsTable pre-request actions.
     */

    return MFD_SUCCESS;
}                               /* dessertAppParamsTable_pre_request */

/**
 * post-request callback
 *
 * Note:
 *   New rows have been inserted into the container, and
 *   deleted rows have been removed from the container and
 *   released.
 *
 * @param user_context
 * @param rc : MFD_SUCCESS if all requests succeeded
 *
 * @retval MFD_SUCCESS : success.
 * @retval MFD_ERROR   : other error (ignored)
 */
int
dessertAppParamsTable_post_request(dessertAppParamsTable_registration *
                                   user_context, int rc)
{
    DEBUGMSGTL(("verbose:dessertAppParamsTable:dessertAppParamsTable_post_request", "called\n"));

    /*
     * TODO:511:o: Perform dessertAppParamsTable post-request actions.
     */

    /*
     * check to set if any rows were changed.
     */
    if (dessertAppParamsTable_dirty_get()) {
        /*
         * check if request was successful. If so, this would be
         * a good place to save data to its persistent store.
         */
        if (MFD_SUCCESS == rc) {
            /*
             * save changed rows, if you haven't already
             */
        }

        dessertAppParamsTable_dirty_set(0);     /* clear table dirty flag */
    }

    return MFD_SUCCESS;
}                               /* dessertAppParamsTable_post_request */


/** @{ */
