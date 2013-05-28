TESTS=tests authuser
SETTINGS=tests.sqlite_test_settings
COVERAGE_COMMAND=


test: test-builtin test-authuser test-customuser

test-builtin:
	cd tests && DJANGO_SETTINGS_MODULE=$(SETTINGS) $(COVERAGE_COMMAND) ./manage.py test --traceback $(TESTS) --verbosity=2

test-authuser:
	+AUTH_USER_MODEL='authuser.User' make test-builtin

test-customuser:
	+AUTH_USER_MODEL='tests.User' make test-builtin

coverage:
	+make test COVERAGE_COMMAND='coverage run --source=authuser --branch --parallel-mode'
	cd tests && coverage combine && coverage html

docs:
	cd docs && $(MAKE) html

.PHONY: test test-builtin test-authuser test-customuser coverage docs
