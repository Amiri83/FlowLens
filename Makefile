VENV ?= .venv
PY := $(VENV)/bin/python
BIN := $(VENV)/bin
DB ?= data/example.db

.PHONY: install test lint fix check demo ui clean reachability-demo scenario-allowed scenario-blocked scenario-unknown

install:  ## create venv and install FlowLens + dev tools
	test -d $(VENV) || python3 -m venv $(VENV)
	$(BIN)/pip install -e '.[dev]'

test:
	$(BIN)/pytest -q

lint:
	$(BIN)/ruff check src tests

fix:
	$(BIN)/ruff check src tests --fix

check: lint test

demo:  ## scan the example stack and trace two paths
	$(BIN)/flowlens scan examples/terraform --db $(DB)
	$(BIN)/flowlens path aws_api_gateway_integration.hello aws_subnet.private_a --db $(DB)
	$(BIN)/flowlens path aws_lb_listener.https aws_vpc.main --db $(DB)

ui:
	$(BIN)/flowlens ui --db $(DB)

# Reachability scenarios (Terraform-only, nothing is applied):
#   A allowed  - Internet -> ALB :443 -> TG -> ECS :8080 fully allowed
#   B blocked  - same, but the app SG allows :80 instead of the TG port 8080
#   C unknown  - same, but the app SGs come from an unresolved variable
SCENARIO = rm -f data/scenario-$(1).db && \
	$(BIN)/flowlens scan examples/reachability/$(1) --db data/scenario-$(1).db > /dev/null && \
	$(BIN)/flowlens reachability internet aws_ecs_service.app --protocol tcp --port 443 --db data/scenario-$(1).db

scenario-allowed:
	$(call SCENARIO,allowed)

scenario-blocked:
	$(call SCENARIO,blocked)

scenario-unknown:
	$(call SCENARIO,unknown)

reachability-demo: scenario-allowed scenario-blocked scenario-unknown

clean:
	rm -rf .pytest_cache .ruff_cache $(DB)
	find . -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} +
