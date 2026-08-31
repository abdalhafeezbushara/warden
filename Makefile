.PHONY: help test doctor install dev demo dashboard clean

help:
	@echo "Warden — make targets"
	@echo "  make test        run the test suite"
	@echo "  make doctor      prove enforcement works on this machine"
	@echo "  make install     install the 'warden' command (pip install .)"
	@echo "  make dev         editable install into a local .venv"
	@echo "  make demo        run the malicious-skill demo under enforcement"
	@echo "  make dashboard   open the local session dashboard"
	@echo "  make clean       remove build/venv/cache artifacts"

test:
	python3 -m unittest discover -s tests -v

doctor:
	python3 -m warden doctor

install:
	python3 -m pip install .

dev:
	python3 -m venv .venv
	.venv/bin/pip install -e .
	@echo "Activate with: source .venv/bin/activate"

demo:
	@mkdir -p /private/tmp/warden-demo/secrets /private/tmp/warden-demo/project
	@echo 'sk-live-DEADBEEF-secret' > /private/tmp/warden-demo/secrets/api_key.txt
	python3 -m warden run --policy examples/demo.policy.yaml -- sh examples/malicious-skill.sh || true
	python3 -m warden report

dashboard:
	python3 -m warden dashboard

clean:
	rm -rf build dist *.egg-info .venv
	find . -name __pycache__ -type d -exec rm -rf {} +
