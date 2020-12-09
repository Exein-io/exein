#ifndef INI_FILE_H_
#define INI_FILE_H_

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include "list.h"

#define NAME_NAME     0
#define NAME_NUMBER   1
#define NUMBER_NAME   2
#define NUMBER_NUMBER 3

#define NAME          0
#define NUMBER        1

#define LEFT_BRACE '['
#define RIGHT_BRACE ']'
#define COMMENT ';'
#define SIGN_OF_EQUAL "=="

#define BASE_URL_FIRST_GROUP 3

#define LINE_LEN 256

#define SectionName(ptr) (ptr)!=NULL?(ptr)->section:"NA"
#define KeyValue(ptr) (ptr)!=NULL?(ptr)->value:"NA"
#define KeyName(ptr) (ptr)!=NULL?(ptr)->key:"NA"

/** @brief max length of each value */
#define VALUE_LEN 256

typedef struct keys {
	struct list_head node;
	char value[VALUE_LEN];
	char key[VALUE_LEN];
	int id;
}keys_t;

typedef struct sections{
	struct list_head node;
	char section[VALUE_LEN];
	keys_t *keys;
}sections_t;

typedef struct group_range {
	int begin;
	int end;
	int group_num;
}group_range_t;

extern group_range_t *g_group;
/** @brief the end of each line */
#define NEW_LINE(c) ('\n' == c || '\r' == c)? 1 : 0

/** @brief delete the end-of-line indicator */
#define DELE_NEW_LINE_INDICATOR(buffer, len) 	\
									if (NEW_LINE(buffer[len - 1])) { \
										if (NEW_LINE(buffer[len - 2])) \
											buffer[len - 2] = '\0';   \
										else  						\
											buffer[len - 1] = '\0';\
									}	

#define STRING_COMPARE(x, equ, y) (strcmp(x, y) equ 0)

int delete_line_break_indicator(char *buffer);
void print_error(char *err_msg);
int read_file_content(const char *file, sections_t *section_head);
int read_ini_file(char * filename, sections_t *section_head);
sections_t *get_section(void *section, sections_t *section_head, char method);
keys_t *get_key(void *section, void *key, sections_t *section_head, char method);
int add_section(char *section_name, sections_t *section_head);
int add_key(char *section_name, char *key_name, char *key_value, sections_t *section_head);
void print_ini(sections_t *section_head);

#define CONFIG_FILE "./config.ini"

#endif //end of INI_FILE_H_

