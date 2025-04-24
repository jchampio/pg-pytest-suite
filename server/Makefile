# A basic PGXS builder for the oauthtest module.

MODULES = oauthtest
PGFILEDESC = "oauthtest - passthrough module to validate OAuth tests"

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
