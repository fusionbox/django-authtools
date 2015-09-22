TESTS=tests authtools
SETTINGS=tests.sqlite_test_settings
COVERAGE_COMMAND=

DJANGO_TGZ=https://github.com/django/django/archive/1.8.4.tar.gz
DJANGO_CHECKSUM=42c8f39e1542db11fa057be3da68b3126c3f639a76eb2ea8733faed0ae0f650d


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

django.tar.gz: export TMP=$(shell mktemp)
django.tar.gz:
	wget "$(DJANGO_TGZ)" -O "$${TMP}"
	echo "$(DJANGO_CHECKSUM) " "$${TMP}" | sha256sum -c
	mv "$${TMP}" "$@"

tests/auth_tests: django.tar.gz
	tar -xf $< --strip-components=2 -C ./tests "django*/tests/auth_tests"

docs:
	cd docs && $(MAKE) html

.PHONY: test test-builtin test-authtools test-customuser coverage docs
