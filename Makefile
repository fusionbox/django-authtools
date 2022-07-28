TESTS=tests authtools
SETTINGS=tests.sqlite_test_settings
COVERAGE_COMMAND=

test: test-builtin test-authtools test-customuser

test-builtin:
	cd tests && DJANGO_SETTINGS_MODULE=$(SETTINGS) $(COVERAGE_COMMAND) ./manage.py test --traceback $(TESTS) --verbosity=2

test-authtools:
	+AUTH_USER_MODEL='authtools.User' make test-builtin

test-customuser:
	+AUTH_USER_MODEL='tests.User' make test-builtin

coverage:
	+make test COVERAGE_COMMAND='coverage run --source=authtools --branch --parallel-mode'
	cd tests && coverage combine && coverage html

docs:
	cd docs && $(MAKE) html

.PHONY: test test-builtin test-authtools test-customuser coverage docs
