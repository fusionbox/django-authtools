TESTS=tests authtools
SETTINGS=tests.sqlite_test_settings
COVERAGE_COMMAND=

# We download the tests from Django and then inherit from them. These environment variables are
# overridden by the tox.ini. If you are adding support for a new version of Django, you can find
# the checksum at https://www.djangoproject.com/m/pgp/Django-x.x.x.checksum.txt
DJANGO_VERSION?=1.8.4
DJANGO_CHECKSUM?=826996c81e1cc773500124d5c19212e4a7681a55ee169fab9085f2b3015a70d8


test: test-builtin test-authtools test-customuser

test-builtin: tests/auth_tests
	cd tests && DJANGO_SETTINGS_MODULE=$(SETTINGS) $(COVERAGE_COMMAND) ./manage.py test --traceback $(TESTS) --verbosity=2

test-authtools: tests/auth_tests
	+AUTH_USER_MODEL='authtools.User' make test-builtin

test-customuser: tests/auth_tests
	+AUTH_USER_MODEL='tests.User' make test-builtin

coverage:
	+make test COVERAGE_COMMAND='coverage run --source=authtools --branch --parallel-mode'
	cd tests && coverage combine && coverage html

django-%.tar.gz: export TMP=$(shell mktemp)
django-%.tar.gz:
	wget "https://www.djangoproject.com/download/$(patsubst django-%.tar.gz,%,$@)/tarball/" -O "$${TMP}"
	echo "$(DJANGO_CHECKSUM) " "$${TMP}" | sha256sum -c
	mv "$${TMP}" "$@"

# Set as phony so that it will be re-copied every time so that we can be sure we have pulled the
# correct version of the Django tests. However, this can be super annoying if you are trying to
# debug by modifying the code in auth_tests. If you want to do that, just comment out the PHONY
# line.
.PHONY: tests/auth_tests
tests/auth_tests: django-$(DJANGO_VERSION).tar.gz
	@-rm -r $@
	tar -xf $< --strip-components=2 -C ./tests "Django-$(DJANGO_VERSION)/tests/auth_tests"

docs:
	cd docs && $(MAKE) html

.PHONY: test test-builtin test-authtools test-customuser coverage docs
