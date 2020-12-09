obj-$(CONFIG_SECURITY_EXEIN) := exein.o
exein-y := exein_lsm.o exein_nn_main.o exein_struct_mappings.o exein_trust.o
ccflags-y := -Wno-declaration-after-statement -Wno-unused-function

$(addprefix $(obj)/,$(exein-y)): $(obj)/exein_nn_defs.h
$(addprefix $(obj)/,$(exein-y)): $(obj)/mkHookh_data/hooks.csv
$(addprefix $(obj)/,$(exein-y)): $(obj)/mkHookh_data/hookspart.ini
$(addprefix $(obj)/,$(exein-y)): $(obj)/exein_nn_defs_comp.h

quiet_cmd_mkHooksh = GENH	$(srctree)/exein_nn_defs.h
	cmd_mkHooksh = $(obj)/../../scripts/exein/mkHookh/mkHookh $(obj)/mkHookh_data/hooks.ini $(obj)/mkHookh_data/config.ini Y >$(srctree)/security/exein/exein_nn_defs.h && chmod +x $(srctree)/scripts/exein/make_define_aliases.sh && $(srctree)/scripts/exein/make_define_aliases.sh >>$(srctree)/security/exein/exein_nn_defs.h

quiet_cmd_mkHookhcomp = GENH	$(srctree)/exein_nn_defs_comp.h
	cmd_mkHookhcomp = $(obj)/../../scripts/exein/mkHookhcomp/mkHookhcomp $(obj)/mkHookh_data/hookspart.ini $(obj)/mkHookh_data/config.ini >$(srctree)/security/exein/exein_nn_defs_comp.h

quiet_cmd_csv2ini = MKINI	$(obj)/mkHookh_data/hookspart.ini
	cmd_csv2ini = chmod +x $(srctree)/scripts/exein/csv2ini.sh && $(srctree)/scripts/exein/csv2ini.sh $(obj)/mkHookh_data/hooks.csv >$(obj)/mkHookh_data/hookspart.ini

quiet_cmd_HeaderParser = PARSE	$(obj)/mkHookh_data/hooks.csv
	cmd_HeaderParser = $(obj)/../../scripts/exein/HeaderParser/HeaderParser < $(srctree)/include/linux/lsm_hooks.h >$(obj)/mkHookh_data/hooks.csv



targets += exein_nn_defs.h
targets += hooks.csv
targets += hookspart.ini
targets += exein_nn_defs_comp.h

$(obj)/exein_nn_defs_comp.h: $(obj)/mkHookh_data/hookspart.ini
	$(call if_changed,mkHookhcomp)

$(obj)/exein_nn_defs.h: FORCE
ifeq ($(wildcard $(obj)/mkHookh_data/.),)
	cp -r $(srctree)/security/exein/mkHookh_data/ $(obj)
endif
	$(call if_changed,mkHooksh)

$(obj)/mkHookh_data/hookspart.ini: $(obj)/mkHookh_data/hooks.csv
	$(call if_changed,csv2ini)

$(obj)/mkHookh_data/hooks.csv: FORCE
	$(call if_changed,HeaderParser)

$(obj)/exein_nn_defs.h: FORCE

FORCE: ;
