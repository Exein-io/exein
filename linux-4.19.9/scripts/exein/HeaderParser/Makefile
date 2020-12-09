hostprogs-y     := HeaderParser
always          := $(hostprogs-y)
HeaderParser-objs   := lex.yy.o HeaderParser.tab.o
HOST_EXTRACFLAGS += -lm

$(obj)/HeaderParser.tab.h: $(src)/HeaderParser.y FORCE
				bison -o/dev/null --defines=$@ -t -l $<

$(obj)/HeaderParser.tab.c: $(src)/HeaderParser.y FORCE
				bison -o $@ $<

$(obj)/lex.yy.o: $(obj)/HeaderParser.tab.h

$(obj)/lex.yy.c: $(src)/HeaderParser.l FORCE
	flex -o $@ $<

# -I needed for generated C source (shipped source)
HOSTCFLAGS_HeaderParser.tab.o := -I$(src)
HOSTCFLAGS_lex.yy.o := -I$(src)
