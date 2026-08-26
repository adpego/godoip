.PHONY: build run test e2e clean

E2E_VENV := tests/e2e/.venv

build:
	go build -o bin/godoip ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...

$(E2E_VENV): tests/e2e/requirements.txt
	python3 -m venv $(E2E_VENV)
	$(E2E_VENV)/bin/pip install -q -r tests/e2e/requirements.txt
	touch $(E2E_VENV)

# End-to-end tests with doipclient/udsoncan against a real server.
e2e: $(E2E_VENV)
	cd tests/e2e && .venv/bin/python -m pytest -q

clean:
	rm -rf bin/
