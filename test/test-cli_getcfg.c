#include "../dessert.h"

int main(int argc, char** argv) {

	dessert_cli_get_cfg(argc,argv);

	dessert_init("TEST", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);


	dessert_run();

	return 0;
}
