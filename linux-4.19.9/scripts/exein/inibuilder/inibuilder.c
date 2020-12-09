#include <stdio.h>
#include "../config.h"
#include <stdlib.h>


int main(int argc, char **argv)
{
	char keynum=0, secnum=3;
	sections_t section_head = {0};
	int tmp;

	if (!((argc!=3)||(argc!=5))) {
		printf("call:\n\tinibuilder file.ini section_name [key_name key_value]\n");
		exit(1);
		}

	read_ini_file(argv[1], &section_head);
        if (argc==3){
		if (tmp=add_section(argv[2], &section_head)){
			printf("section ADD FAIL! (%d)\n", tmp);
			return 1;
			}
		} else {
		if (tmp=add_key(argv[2],argv[3],argv[4], &section_head)){
			printf("Key ADD FAIL! in [%s] <- %s=%s - %d\n",argv[2],argv[3],argv[4], tmp);
			return 1;
			}
		}
	print_ini(&section_head);
	return 0;
}
