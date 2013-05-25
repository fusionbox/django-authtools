TESTS=tests authuser
SETTINGS=tests.sqlite_test_settings
COVERAGE_COMMAND=

test:
	cd tests && DJANGO_SETTINGS_MODULE=$(SETTINGS) $(COVERAGE_COMMAND) ./manage.py test --traceback $(TESTS) --verbosity=2

coverage:
	+make test COVERAGE_COMMAND='coverage run --source=authuser --branch'
	cd tests && coverage html

.PHONY: test
