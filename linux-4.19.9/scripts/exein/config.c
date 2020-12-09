#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "config.h"
#include "list.h"

/*
 * INTERNAL - NOT EXPORTED
 */
void print_error(char *err_msg)
{
	printf("%s\n", err_msg);
	exit(0);
}

/*
 * @brief delete_line_break_indicator
 * @buffer[in,out]
 * @NOTE:
 * detete the last one or two character which is '\n' or 'r'
 * INTERNAL - NOT EXPORTED
 */
int delete_line_break_indicator(char *buffer)
{
	int len = strlen(buffer), i, j = len - 1;
	for (i = j; i >= 0; i--) {
		if (!isspace(buffer[i])) {
			if (i == j) {
				break;
			}
			else {
				buffer[i + 1] = '\0';
				break;
			}
		}
	}

	DELE_NEW_LINE_INDICATOR(buffer, len);
#if 0
	if (NEW_LINE(buffer[len - 1])) {
		if (NEW_LINE(buffer[len - 2]))
			buffer[len - 2] = '\0';
		else
			buffer[len - 1] = '\0';
	}
#endif
	return 0;
}

/*
 * @read_file_content
 * @file         [in] the direcotry of category.ini
 * @section_head [in,out]
 * Return 1 on success and populates the section_heads, 0 elsewhere.
 */
int read_file_content(const char *file, sections_t *section_head)
{
	FILE *fp = NULL;
	char * ret_buf, contents[LINE_LEN] = {0}, *saveptr = NULL, *pcon = contents;
	sections_t *section_node = NULL;
	keys_t *keys;

	assert(file !=NULL);

	if ((fp = fopen(file,"r")) == NULL) {
		fprintf(stderr, "Open [%s] %s\n", file ,strerror(errno));
		return 0;
	}

	while (fgets(pcon, LINE_LEN, fp)){
		/** @brief skip all the space character that contains
			('\r', '\n', '\f', '\t', '\v')
		*/
		while (isspace(*pcon)) {
			pcon++;
			}

		/** @brief find the section '[]' */
		if (*pcon == LEFT_BRACE) {
			if ((ret_buf = strchr(pcon, RIGHT_BRACE))) {
				if ((section_node = (sections_t *)malloc(sizeof(sections_t))) == NULL) {
					perror("MALLOC:");
					return 0;
					}
				memset(section_node, 0, sizeof(sections_t));
				memcpy(section_node->section, pcon + 1, ret_buf - pcon - 1);
				list_add_tail(&section_node->node, &section_head->node);
				}else {
					print_error("syntex error , there are need ']'");
					}
			}else if (*pcon == COMMENT) {
				/** @brief this is a comment line and ignore it */
				continue;
				}else {

				/** @brief find all the keys and value which under the section found */
				if (section_node == NULL) {
					print_error("syntex error, there are no '[]'");
					}

				int i = 0;
				if (section_node->keys == NULL) {
					if ((section_node->keys = (keys_t *)malloc(sizeof(keys_t))) == NULL){
						perror("MALLOC:");
						return 0;
						}
				memset(section_node->keys, 0, sizeof(keys_t));
				INIT_LIST_HEAD(&section_node->keys->node);
				}
			if ((keys = (keys_t *)malloc(sizeof(keys_t))) == NULL) {
				perror("MALLOC:");
				exit(0);
				}
			memset(keys, 0, sizeof(keys_t));

			while ((ret_buf = strtok_r(pcon, SIGN_OF_EQUAL, &saveptr))) {
				if (i == 0) {
					delete_line_break_indicator(ret_buf);
					memcpy(keys->key, ret_buf, strlen(ret_buf)); }else if (i == 1) {
					delete_line_break_indicator(ret_buf);
					memcpy(keys->value, ret_buf, strlen(ret_buf));
					}
				pcon = NULL;
				i++;
				}

			if (i == 0) {
				free(keys);
				}else list_add_tail(&keys->node, &section_node->keys->node);
			}

		memset(contents, 0, LINE_LEN);
		pcon = contents;
	}

	fclose(fp);
	return 1;
}

/*
 * @get_section
 * @section      [in]
 * @section_head [in] the struct which stores the head of section list
 * @method       [in] defines the type of data specified to access the structure. 
 *                    Valid methods includes: NAME, NUMBER.
 * Return a pointer to the section having the specified characteristics if found; NULL elsewhere.
 */

sections_t *get_section(void *section, sections_t *section_head, char method)
{
	assert(section != NULL);
	assert(section_head != NULL);
	assert(method <= NUMBER);

	struct list_head *pos = NULL;
	sections_t * tmp_node = NULL;

	switch (method) {
		case NAME:
		list_for_each(pos, &section_head->node) {
			tmp_node = (sections_t *)container_of(pos, sections_t, node);
			if (STRING_COMPARE((char *)section, ==, tmp_node->section)) {
				return tmp_node;
				}
			}
		break;
		case NUMBER:
		{
		int ct=0;
		list_for_each(pos, &section_head->node) {
			tmp_node = (sections_t *)container_of(pos, sections_t, node);
			if (ct==*((int *)section)) {
				return tmp_node;
				}
			ct++;
			}
		}
		break;
		}
	return NULL;
}

/*
 * @add_section
 * @section_name [in]
 * @section_head [in/out] the struct which stores the head of section list
 * Return 0 on success others on failure
 *        1 section exist
 *        2 memory alloc fail
 */

int add_section(char *section_name, sections_t *section_head){
	sections_t *section_node = NULL;

	if (get_section(section_name, section_head, NAME)){
		return 1;
		}
	if ((section_node = (sections_t *)malloc(sizeof(sections_t))) == NULL) {
		return 2;
		}
	memset(section_node, 0, sizeof(sections_t));
	memcpy(section_node->section, section_name, strlen(section_name));
	list_add_tail(&section_node->node, &section_head->node);
	return 0;
}

/*
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
*/


/*
 * @add_key
 * @key_name [in]
 * @key_value [in]
 * @section_head [in/out] the struct which stores the head of section list
 * Return 0 on success others on failure
 *        1 section not found
 *        2 memory alloc fail
 */

int add_key(char *section_name, char *key_name, char *key_value, sections_t *section_head){
        sections_t *section_node;
	keys_t *tmp_key;

        if (!(section_node=get_section(section_name, section_head, NAME))){
		fflush(stdout);
                return 1;
                }

	fflush(stdout);
	if ((tmp_key = (keys_t *)malloc(sizeof(keys_t))) == NULL){
		return 2;
		}
	memset(tmp_key, 0, sizeof(keys_t));
	memcpy(tmp_key->key, key_name, strlen(key_name));
	memcpy(tmp_key->value, key_value, strlen(key_value));

        if (section_node->keys == NULL) {
		if ((section_node->keys = (keys_t *)malloc(sizeof(keys_t))) == NULL){
                	return 2;
                	}
		memset(section_node->keys, 0, sizeof(keys_t));
		INIT_LIST_HEAD(&section_node->keys->node);
		}
	list_add_tail(&tmp_key->node, &section_node->keys->node);
        return 0;
}




/*
 * @get_key
 * @section      [in]
 * @key          [in]
 * @section_head [in] the struct which stores the head of section list
 * @method       [in] defines the type of data specified to access the structure. 
 *                    Valid methods includes: NAME_NAME, NAME_NUMBER, NUMBER_NAME, NUMBER_NUMBER.
 * Returns a pointer to the specified key laying in the specified section if found, NULL elsewhere.
 */

keys_t *get_key(void *section, void *key, sections_t *section_head, char method)
{
	assert(section != NULL);
	assert(section_head != NULL);
	assert(key != NULL);
	assert(method <= NUMBER_NUMBER);

	struct list_head *pos = NULL, *pos_child = NULL;
	sections_t * tmp_node = NULL;
	keys_t *tmp_key = NULL;


	switch (method) {
		case NAME_NAME:
		list_for_each(pos, &section_head->node) {
			tmp_node = (sections_t *)container_of(pos, sections_t, node);
			if (STRING_COMPARE((char *)section, ==, tmp_node->section)) {
				list_for_each(pos_child, &tmp_node->keys->node) {
					tmp_key = (keys_t *)container_of(pos_child, keys_t, node);
					if (STRING_COMPARE((char *)key, ==, tmp_key->key)) {
						return tmp_key;
						}
					}
				}
			}
		break;
		case NAME_NUMBER:
		{
		int ct=0;
		list_for_each(pos, &section_head->node) {
			tmp_node = (sections_t *)container_of(pos, sections_t, node);
			if (STRING_COMPARE((char *)section, ==, tmp_node->section)) {
				list_for_each(pos_child, &tmp_node->keys->node) {
					tmp_key = (keys_t *)container_of(pos_child, keys_t, node);
					if (*((int *)key)==ct) {
						return tmp_key;
						}
					ct++;
					}
				}
			}
		}
		break;
		case NUMBER_NAME:
		{
		int ct=0;
		list_for_each(pos, &section_head->node) {
			tmp_node = (sections_t *)container_of(pos, sections_t, node);
			if (*((int *) section)==ct) {
				list_for_each(pos_child, &tmp_node->keys->node) {
					tmp_key = (keys_t *)container_of(pos_child, keys_t, node);
					if (STRING_COMPARE((char *)key, ==, tmp_key->key)) {
						return tmp_key;
						}
					}
				}
			ct++;
			}
		}
		break;
		case NUMBER_NUMBER:
		{
		int ctk=0,cts=0;
		list_for_each(pos, &section_head->node) {
			tmp_node = (sections_t *)container_of(pos, sections_t, node);
			if (*((int *) section)==cts)  {
				list_for_each(pos_child, &tmp_node->keys->node) {
					tmp_key = (keys_t *)container_of(pos_child, keys_t, node);
					if (*((int *)key)==ctk) {
						return tmp_key;
						}
					ctk++;
					}
				}
			cts++;
			}
		}
		break;
		}
	return NULL;
}

void print_ini(sections_t *section_head){
	sections_t *tmp_sec;
	keys_t *tmp_key;

	for (char i=0;(tmp_sec=get_section(&i,section_head, NUMBER)); i++){
//		printf("[%s] debug: key=%p\n", SectionName(tmp_sec), tmp_sec->keys);
		printf("[%s]\n", SectionName(tmp_sec));
		if (tmp_sec->keys){
	                for (char j=0;(tmp_key=get_key(&i,&j,section_head, NUMBER_NUMBER)); j++){
        	                printf("%s=%s\n", KeyName(tmp_key), KeyValue(tmp_key));
                	        }
			}
                }
}




/*
 * @read_ini_file
 * @filename[in] the name of *.ini file
 * @section_head[in,out]
 */
int read_ini_file(char * filename, sections_t *section_head)
{
//	char buffer[VALUE_LEN] = {0};
	/** @brief init the head of list */
	INIT_LIST_HEAD(&section_head->node);


	/** @brief parse the whole .ini file and
		store information in section_head list */
	read_file_content(filename, section_head);

	return 0;
}
