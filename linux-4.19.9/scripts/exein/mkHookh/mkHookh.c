#include <stdio.h>
#include <stdlib.h>
#include "../config.h"
#define FILE_BUFFER_SIZE 1048510
#define MAXCHAR 1024

int main(int argc, char **argv)
{
	char keynum, secnum;
	sections_t *tmp_sec;
	keys_t *tmp_key;
	sections_t section_head = {0};
	sections_t config_head = {0};
	int pos=0, cur_array_pos=0;
	FILE *fp;
	char str[MAXCHAR];
	char *prev="0";
	char *prevVal;


        if (argc!=4) {
                printf("call:\n\tmkHookh hooks.ini config.ini [Y/N]\n");
                exit(1);
                }


	srand(time(NULL));
	char *H_file=(char *)malloc(FILE_BUFFER_SIZE);
        memset(H_file,0, FILE_BUFFER_SIZE);
	read_ini_file(argv[1], &section_head);
	read_ini_file(argv[2], &config_head);

/*
  _                    _
 | |                  | |
 | |__   ___  __ _  __| | ___ _ __ ___
 | '_ \ / _ \/ _` |/ _` |/ _ \ '__/ __|
 | | | |  __/ (_| | (_| |  __/ |  \__ \
 |_| |_|\___|\__,_|\__,_|\___|_|  |___/

*/
	pos+=sprintf((H_file+pos),"#include \"exein_nn_defs_comp.h\"\n", prev, prevVal );
	if (strncmp(argv[3],"Y",1)==0) {
		int counter=0;
		for (int i=0;tmp_sec=get_section(&i,&section_head, NUMBER); i++){
			pos+=sprintf((H_file+pos),"/**********/\n", tmp_sec);
			for (int j=0; tmp_key=get_key(&i,&j,&section_head, NUMBER_NUMBER); j++){
				pos+=sprintf((H_file+pos),"#define EXEIN_%s_ID %d\n", KeyName(tmp_key), counter);
				counter++;
				}
			}
		}
	pos+=sprintf((H_file+pos),"\n\n/********************************************************************************************************/\n");
	pos+=sprintf((H_file+pos),"#define EXEIN_0_ARG1_POS  0\n");
	pos+=sprintf((H_file+pos),"#define HOOK_ID  1\n");
	pos+=sprintf((H_file+pos),"#define HOOK_CURRENT_PROCESS  1\n");
	pos+=sprintf((H_file+pos),"#define HOOK_CURRENT_PROCESS_TAG  1\n");
	for (int i=0;tmp_sec=get_section(&i,&section_head, NUMBER); i++){
		pos+=sprintf((H_file+pos),"/**********/\n", tmp_sec);
		for (int j=0; tmp_key=get_key(&i,&j,&section_head, NUMBER_NUMBER); j++){

			pos+=sprintf((H_file+pos),"#define EXEIN_%s_ARG1_POS	EXEIN_%s_ARG1_POS + %s\n", KeyName(tmp_key), prev, prev);
			pos+=sprintf((H_file+pos),"#define EXEIN_%s_SIZE 	%s\n", KeyName(tmp_key), KeyValue(tmp_key));
			//cur_array_pos+=atoi(KeyValue(tmp_key));
                        prev=KeyName(tmp_key);
			prevVal=KeyValue(tmp_key);
			}
		}
	
	pos+=sprintf((H_file+pos),"\n\n/********************************************************************************************************/\n");
	pos+=sprintf((H_file+pos),"\n\n#define EXEIN_NN_INPUT_SIZE EXEIN_%s_ARG1_POS + %s\n", prev, prevVal );
	pos+=sprintf((H_file+pos),"\n\n/********************************************************************************************************/\n");
	pos+=sprintf((H_file+pos),"\n\n#define SEEDRND %d\n", rand() );



/*
              _               _
             | |             | |
   ___  _   _| |_ _ __  _   _| |_
  / _ \| | | | __| '_ \| | | | __|
 | (_) | |_| | |_| |_) | |_| | |_
  \___/ \__,_|\__| .__/ \__,_|\__|
                 | |
                 |_|
*/
	fp = fopen(KeyValue(get_key("files","header",&config_head, NAME_NAME)), "r");
	if (fp == NULL){
		printf("Could not open header file\n");
		return 1;
		}
	while (fgets(str, MAXCHAR, fp) != NULL) printf("%s", str);
	fclose(fp);
	puts(H_file);
        fp = fopen(KeyValue(get_key("files","footer",&config_head, NAME_NAME)), "r");
        if (fp == NULL){
                printf("Could not open header file\n");
                return 1;
                }
        while (fgets(str, MAXCHAR, fp) != NULL) printf("%s", str);
        fclose(fp);
	return 0;
}
