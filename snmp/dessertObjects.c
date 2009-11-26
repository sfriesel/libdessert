/**
 * Note: this file originally auto-generated by mib2c using
 *        : mib2c.scalar.conf 11805 2005-01-07 09:37:18Z dts12 $
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "../dessert_internal.h"

/** Initializes the dessertObjects module */
void
init_dessertObjects(void)
{
    static oid      dessertMeshifNumber_oid[] =
        { 1, 3, 6, 1, 4, 1, 18898, 0, 19, 10, 1, 1, 4 };
    static oid      applicationVersion_oid[] =
        { 1, 3, 6, 1, 4, 1, 18898, 0, 19, 10, 1, 1, 3, 2 };
    static oid      protocollShortName_oid[] =
        { 1, 3, 6, 1, 4, 1, 18898, 0, 19, 10, 1, 1, 3, 3 };

    DEBUGMSGTL((AGENT, "Initializing\n"));

    netsnmp_register_scalar(netsnmp_create_handler_registration
                            ("dessertMeshifNumber",
                             handle_dessertMeshifNumber,
                             dessertMeshifNumber_oid,
                             OID_LENGTH(dessertMeshifNumber_oid),
                             HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration
                            ("applicationVersion",
                             handle_applicationVersion,
                             applicationVersion_oid,
                             OID_LENGTH(applicationVersion_oid),
                             HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration
                            ("protocollShortName",
                             handle_protocollShortName,
                             protocollShortName_oid,
                             OID_LENGTH(protocollShortName_oid),
                             HANDLER_CAN_RONLY));
}

int
handle_dessertMeshifNumber(netsnmp_mib_handler *handler,
                           netsnmp_handler_registration *reginfo,
                           netsnmp_agent_request_info *reqinfo,
                           netsnmp_request_info *requests)
{
	u_char meshif_count;

	dessert_meshif_t *meshif;

	DL_FOREACH(dessert_meshiflist_get(), meshif){
		meshif_count++;
	}

	/*
     * We are never called for a GETNEXT if it's registered as a
     * "instance", as it's "magically" handled for us.  
     */

    /*
     * a instance handler also only hands us one request at a time, so
     * we don't need to loop over a list of requests; we'll only get one. 
     */

    switch (reqinfo->mode) {

    case MODE_GET:
    	DEBUGMSGTL((AGENT, "handle_dessertMeshifNumber:MODE_GET\n"));
        snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                                 (u_char *) &meshif_count, sizeof(u_char));
        break;


    default:
        /*
         * we should never get here, so this is a really bad error 
         */
        snmp_log(LOG_ERR,
                 "unknown mode (%d) in handle_dessertMeshifNumber\n",
                 reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
handle_applicationVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info *reqinfo,
                          netsnmp_request_info *requests)
{
    /*
     * We are never called for a GETNEXT if it's registered as a
     * "instance", as it's "magically" handled for us.  
     */

    /*
     * a instance handler also only hands us one request at a time, so
     * we don't need to loop over a list of requests; we'll only get one. 
     */

    switch (reqinfo->mode) {

    case MODE_GET:
    	DEBUGMSGTL((AGENT, "handle_applicationVersion:MODE_GET\n"));
        snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                                 (u_char *) &dessert_ver, sizeof(dessert_ver));
        break;


    default:
        /*
         * we should never get here, so this is a really bad error 
         */
        snmp_log(LOG_ERR,
                 "unknown mode (%d) in handle_applicationVersion\n",
                 reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
handle_protocollShortName(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info *reqinfo,
                          netsnmp_request_info *requests)
{
    /*
     * We are never called for a GETNEXT if it's registered as a
     * "instance", as it's "magically" handled for us.  
     */

    /*
     * a instance handler also only hands us one request at a time, so
     * we don't need to loop over a list of requests; we'll only get one. 
     */

    switch (reqinfo->mode) {

    case MODE_GET:
    	DEBUGMSGTL((AGENT, "handle_protocollShortName:MODE_GET\n"));
        snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                 (u_char *) dessert_proto, DESSERT_PROTO_STRLEN+1);
        break;


    default:
        /*
         * we should never get here, so this is a really bad error 
         */
        snmp_log(LOG_ERR,
                 "unknown mode (%d) in handle_protocollShortName\n",
                 reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
