COMPOSE := docker compose -f compose.yaml

.DEFAULT_GOAL := help

.PHONY: help compose-config tools check test generate-xdr check-xdr nfs4-fixtures tooling-policy \
	pynfs-image pynfs-smoke pynfs test-pynfs pynfs-with-kdc test-gss \
	kdc-up kdc-status kdc-logs kdc-down

help:
	@echo "Docker-first developer targets:"
	@echo "  make check            Run the complete repository gate"
	@echo "  make test             Run all Rust targets with default features"
	@echo "  make generate-xdr     Regenerate the licensed RFC 7531 XDR source"
	@echo "  make check-xdr        Diff RFC 7531 XDR and run codec conformance"
	@echo "  make nfs4-fixtures    Run raw NFSv4 RPC/XDR fixture tests"
	@echo "  make tooling-policy   Check local script/runtime policy"
	@echo "  make pynfs-smoke      Build and smoke-check pinned pynfs"
	@echo "  make pynfs SERVER=host EXPORT=/path [PYNFS_TESTS=all]"
	@echo "  make test-pynfs SERVER=host EXPORT=/path [PYNFS_TESTS=all]"
	@echo "  make pynfs-with-kdc SERVER=host EXPORT=/path [PYNFS_TESTS=all]"
	@echo "  make test-gss         Run portable RPCSEC_GSS unit and real-KDC tests"
	@echo "  make kdc-up           Start the isolated test KDC"
	@echo "  make kdc-status       Verify the test principals"
	@echo "  make kdc-down         Stop the test KDC without deleting its state"

compose-config:
	$(COMPOSE) config --quiet

tools:
	$(COMPOSE) build tools

check:
	$(COMPOSE) run --rm --build tools ./tests/run_ci.sh

test:
	$(COMPOSE) run --rm --build tools cargo test --locked --all-targets

generate-xdr:
	$(COMPOSE) run --rm --build tools ./tools/regenerate-xdr.sh --write

check-xdr:
	$(COMPOSE) run --rm --build tools ./tools/regenerate-xdr.sh --check

nfs4-fixtures:
	$(COMPOSE) run --rm --build tools cargo test --locked --test nfs4_fixtures

tooling-policy:
	$(COMPOSE) run --rm --build tools ./tests/check_local_tooling.sh

pynfs-image:
	$(COMPOSE) --profile interop build pynfs

pynfs-smoke:
	$(COMPOSE) --profile interop run --rm --build pynfs --self-test

pynfs:
	$(COMPOSE) --profile interop run --rm --build \
		-e PYNFS_SERVER="$(SERVER)" \
		-e PYNFS_EXPORT="$(or $(EXPORT),/)" \
		-e PYNFS_TESTS="$(or $(PYNFS_TESTS),all)" \
		pynfs

test-pynfs: pynfs

test-gss: kdc-up
	@cleanup() { $(COMPOSE) --profile kerberos stop kdc; }; \
	trap 'trap - EXIT; cleanup; exit 130' HUP INT TERM; \
	trap cleanup EXIT; \
	status=0; \
	$(COMPOSE) --profile kerberos run --rm --build tools \
		sh -ec 'cargo test --locked --lib rpc::gss:: && cargo test --locked --test gss_kdc -- --ignored --exact portable_sspi_round_trips_against_real_kdc_for_rpcsec_gss_v1_and_v2' \
		|| status=$$?; \
	exit $$status

pynfs-with-kdc: kdc-up
	$(COMPOSE) --profile interop --profile kerberos run --rm --build \
		-e PYNFS_KINIT=1 \
		-e PYNFS_SERVER="$(SERVER)" \
		-e PYNFS_EXPORT="$(or $(EXPORT),/)" \
		-e PYNFS_TESTS="$(or $(PYNFS_TESTS),all)" \
		pynfs

kdc-up:
	$(COMPOSE) --profile kerberos up --detach --build --wait kdc

kdc-status:
	$(COMPOSE) --profile kerberos exec kdc \
		kadmin --local --realm=NFSEMBED.TEST \
		--config-file=/etc/krb5kdc/kdc.conf \
		get nfs/server.nfsembed.test@NFSEMBED.TEST
	$(COMPOSE) --profile kerberos exec kdc \
		kadmin --local --realm=NFSEMBED.TEST \
		--config-file=/etc/krb5kdc/kdc.conf \
		get client@NFSEMBED.TEST

kdc-logs:
	$(COMPOSE) --profile kerberos logs kdc

kdc-down:
	$(COMPOSE) --profile kerberos stop kdc
