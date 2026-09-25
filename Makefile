VENV ?= .venv
PY := $(VENV)/bin/python
BIN := $(VENV)/bin
DB ?= data/example.db

.PHONY: install test lint fix check demo ui clean

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

clean:
	rm -rf .pytest_cache .ruff_cache $(DB)
	find . -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} +
