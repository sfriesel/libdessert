#include "../dessert.h"

int main(int argc, char** argv) {

	FILE* cfg = dessert_cli_get_cfg(argc,argv);
	dessert_init("TEST", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);
	cli_file(dessert_cli, cfg, PRIVILEGE_PRIVILEGED, MODE_CONFIG);

	dessert_cli_run();
	dessert_set_cli_port(12354);
	dessert_run();


	return 0;
}
