%{

#include <stdio.h>
#include <stdlib.h>

extern int yylex();
extern int yyparse();
extern FILE* yyin;

void yyerror(const char* s);
%}

%union {
	int ival;
	float fval;
	char *sval;
}


%token PO PC COLON COMMA STRUCT UNSIGNED CONST INT LONG SIGNED SHORT CHAR VOID AST ENUM UNION
%token<sval> ARGNAME ARGTYPE FUNNAME TYPE IDENTIFIER
%type<sval> statement arguments argument type argname funname

%%

definitions:  /* empty */
	|definitions instruction
	;

instruction: COLON                                  
	|statement COLON                            { printf("\n");}
	;

statement:  type funname PO arguments               
	;

arguments: argument
	| arguments argument                        
	;

argument: type argname                              
	| VOID PC                                   
	;

argname: IDENTIFIER COMMA                           
	|IDENTIFIER PC                              
	;
funname: PO AST IDENTIFIER PC                       { printf("%s,", $3); }


type: IDENTIFIER                                    { printf("%s,", $1); }
	| UNION IDENTIFIER                          { printf("union %s,", $2); }
	| ENUM IDENTIFIER                           { printf("enum %s,", $2); }
	| CONST IDENTIFIER                          { printf("const  %s,", $2); }
	| CONST STRUCT IDENTIFIER                   { printf("const struct %s,", $3); }
	| STRUCT IDENTIFIER                         { printf("struct %s,", $2); }
	| CHAR                                      { printf("char,"); }
	| CONST CHAR                                { printf("const char,"); }
	| SIGNED CHAR                               { printf("signed char,"); }
	| UNSIGNED CHAR                             { printf("unsigned char,"); }
	| SHORT                                     { printf("short,"); }
	| SHORT INT                                 { printf("short int,"); }
	| SIGNED SHORT                              { printf("signed short,"); }
	| SIGNED SHORT INT                          { printf("signed shot int,"); }
	| UNSIGNED SHORT                            { printf("unsigned short,"); }
	| UNSIGNED SHORT INT                        { printf("unsigned short int,"); }
	| INT                                       { printf("int,"); }
	| SIGNED                                    { printf("signed,"); }
	| SIGNED INT                                { printf("signed int,"); }
	| UNSIGNED                                  { printf("unsigned,"); }
	| UNSIGNED INT                              { printf("unsigned int,"); }
	| LONG                                      { printf("long,"); }
	| LONG INT                                  { printf("long int,"); }
	| SIGNED LONG                               { printf("signed long,"); }
	| SIGNED LONG INT                           { printf("signed long int,"); }
	| UNSIGNED LONG                             { printf("unsigned long,"); }
	| UNSIGNED LONG INT                         { printf("unsigned long int,"); }
	| LONG LONG                                 { printf("long long,"); }
	| LONG LONG INT                             { printf("long long int,"); }  
	| SIGNED LONG LONG                          { printf("signed long long,"); }
	| SIGNED LONG LONG INT                      { printf("signed long long int,"); }
	| UNSIGNED LONG LONG                        { printf("unsigned long long,"); }
	| UNSIGNED LONG LONG INT                    { printf("unsigned long long int,"); }
	| VOID                                      { printf("void,"); }
	| IDENTIFIER AST                            { printf("%s *,", $1); }
	| UNION IDENTIFIER AST                      { printf("union %s *,", $2); }
	| CONST IDENTIFIER AST                      { printf("const struct %s,", $2); }
	| CONST STRUCT IDENTIFIER AST               { printf("const struct %s *,", $3); }
	| STRUCT IDENTIFIER AST                     { printf("struct %s *,", $2); }
	| CHAR AST                                  { printf("char *,"); }
	| CONST CHAR AST                            { printf("const char *,"); }
	| SIGNED CHAR AST                           { printf("signed char *,"); }
	| UNSIGNED CHAR AST                         { printf("unsigned char *,"); }
	| SHORT AST                                 { printf("short *,"); }
	| SHORT INT AST                             { printf("short int *,"); }
	| SIGNED SHORT AST                          { printf("signed short *,"); }
	| SIGNED SHORT INT AST                      { printf("signed shot int *,"); }
	| UNSIGNED SHORT AST                        { printf("unsigned short *,"); }
	| UNSIGNED SHORT INT AST                    { printf("unsigned short int *,"); }
	| INT AST                                   { printf("int *,"); }
	| SIGNED AST                                { printf("signed *,"); }
	| SIGNED INT AST                            { printf("signed int *,"); }
	| UNSIGNED AST                              { printf("unsigned *,"); }
	| UNSIGNED INT AST                          { printf("unsigned int *,"); }
	| LONG AST                                  { printf("long *,"); }
	| LONG INT AST                              { printf("long int *,"); }
	| SIGNED LONG AST                           { printf("signed long *,"); }
	| SIGNED LONG INT AST                       { printf("signed long int *,"); }
	| UNSIGNED LONG AST                         { printf("unsigned long *,"); }
	| UNSIGNED LONG INT AST                     { printf("unsigned long int *,"); }
	| LONG LONG AST                             { printf("long long *,"); }
	| LONG LONG INT AST                         { printf("long long int *,"); }  
	| SIGNED LONG LONG AST                      { printf("signed long long *,"); }
	| SIGNED LONG LONG INT AST                  { printf("signed long long int *,"); }
	| UNSIGNED LONG LONG AST                    { printf("unsigned long long *,"); }
	| UNSIGNED LONG LONG INT AST                { printf("unsigned long long int *,"); }
	| CONST VOID AST                            { printf("const void *,"); }
	| VOID AST                                  { printf("void *,"); }
	| IDENTIFIER AST AST                        { printf("%s **,", $1); }
	| CONST IDENTIFIER AST AST                  { printf("const struct %s,", $2); }
	| CONST STRUCT IDENTIFIER AST AST           { printf("const struct %s **,", $3); }
	| STRUCT IDENTIFIER AST AST                 { printf("struct %s **,", $2); }
	| CHAR AST AST                              { printf("char **,"); }
	| CONST CHAR AST AST                        { printf("const char **,"); }
	| SIGNED CHAR AST AST                       { printf("signed char **,"); }
	| UNSIGNED CHAR AST AST                     { printf("unsigned char **,"); }
	| SHORT AST AST                             { printf("short **,"); }
	| SHORT INT AST AST                         { printf("short int **,"); }
	| SIGNED SHORT AST AST                      { printf("signed short **,"); }
	| SIGNED SHORT INT AST AST                  { printf("signed shot int **,"); }
	| UNSIGNED SHORT AST AST                    { printf("unsigned short **,"); }
	| UNSIGNED SHORT INT AST AST                { printf("unsigned short int **,"); }
	| INT AST AST                               { printf("int **,"); }
	| SIGNED AST AST                            { printf("signed **,"); }
	| SIGNED INT AST AST                        { printf("signed int *,"); }
	| UNSIGNED AST AST                          { printf("unsigned **,"); }
	| UNSIGNED INT AST AST                      { printf("unsigned int **,"); }
	| LONG AST AST                              { printf("long **,"); }
	| LONG INT AST AST                          { printf("long int **,"); }
	| SIGNED LONG AST AST                       { printf("signed long **,"); }
	| SIGNED LONG INT AST AST                   { printf("signed long int **,"); }
	| UNSIGNED LONG AST AST                     { printf("unsigned long **,"); }
	| UNSIGNED LONG INT AST AST                 { printf("unsigned long int **,"); }
	| LONG LONG AST AST                         { printf("long long **,"); }
	| LONG LONG INT AST AST                     { printf("long long int **,"); }  
	| SIGNED LONG LONG AST AST                  { printf("signed long long **,"); }
	| SIGNED LONG LONG INT AST AST              { printf("signed long long int **,"); }
	| UNSIGNED LONG LONG AST AST                { printf("unsigned long long **,"); }
	| UNSIGNED LONG LONG INT AST AST            { printf("unsigned long long int **,"); }
	| CONST VOID AST AST                        { printf("const void **,"); }
	| VOID AST AST                              { printf("void **,"); }
	;
%%
int main() {
	yyin = stdin;
	yyparse();
	return 0;
}

void yyerror(const char* s) {
	fprintf(stderr, "Parse error: %s %s,", yylval.sval, s);
	exit(1);
}
