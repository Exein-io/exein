%option noyywrap

%{
#include <stdio.h>
#include <stdlib.h>

#include "HeaderParser.tab.h"

#define YY_DECL int yylex()

int collect=0, typename=0;

char *buffer;

%}



%%

"union security_list_options {"	{
				 collect=1;
				}
"struct"			{
				 if (collect) {
					 return STRUCT;
					}
				}
"unsigned"			{
				 if (collect) {
					 return UNSIGNED;
					}
				}
"long"				{
				 if (collect) {
					 return LONG;
					}
				}
"int"				{
				 if (collect) {
					 return INT;
					}
				}
"signed"			{
				 if (collect) {
					 return SIGNED;
					}
				}
"short"				{
				 if (collect) {
					 return SHORT;
					}
				}
"char"				{
				 if (collect) {
					 return CHAR;
					}
				}
"void"				{
				 if (collect) {
					 return VOID;
					}
				}
"const"                        {
                                 if (collect) {
					 return CONST;
                                        }
                                }
"enum"                        {
                                 if (collect) {
					 return ENUM;
                                        }
                                }
"union"                        {
                                 if (collect) {
					 return UNION;
                                        }
                                }

"#ifdef "[A-Z_]+		;//{printf("ifdef skipped\n");}
"#endif"			;//{printf("endif skipped\n");}
"__"[a-z]+			;//{printf("annotation skipped\n");}
"/*"[A-Za-z0-9_ ]*"*/"		;//{printf("skip comments skipped\n");}
[A-Za-z0-9_]+			{
				 if (collect) {
					 yylval.sval=(char *) malloc(256);
					 strcpy(yylval.sval,yytext);
					 return IDENTIFIER; 
					}
                                }
"{"				{
				 if (collect) { 
					}
				}
"}"				{
				 if (collect) {
					 collect=0;
					}
				}
"("				{
				 if (collect) {
					 return PO; 
					}
				}
")"				{
				 if (collect) {
					 return PC;
					}
				}
"*"				{
				 if (collect) {
					 return AST;
					}
				}
","				{
				 if (collect) {
					 return COMMA;
					}
				}
";"				{
				 if (collect) { 
					 return COLON;
					}
				}
[ \t\r\n]			;
.				;

%%
