[![Actions Status](https://github.com/lyz-code/pass-collaborate/workflows/Tests/badge.svg)](https://github.com/lyz-code/pass-collaborate/actions)
[![Actions Status](https://github.com/lyz-code/pass-collaborate/workflows/Build/badge.svg)](https://github.com/lyz-code/pass-collaborate/actions)
[![Coverage Status](https://coveralls.io/repos/github/lyz-code/pass-collaborate/badge.svg?branch=main)](https://coveralls.io/github/lyz-code/pass-collaborate?branch=main)

A pass extension that helps collectives manage the access to their passwords

# Installing

```bash
pip install pass-collaborate
```

# A Simple Example

```python
{! examples/simple-example.py !} # noqa
```

# References

As most open sourced programs, `pass-collaborate` is standing on the shoulders of
giants, namely:

[Pytest](https://docs.pytest.org/en/latest)
: Testing framework, enhanced by the awesome
    [pytest-cases](https://smarie.github.io/python-pytest-cases/) library that made
    the parametrization of the tests a lovely experience.

[Mypy](https://mypy.readthedocs.io/en/stable/)
: Python static type checker.

[Flakeheaven](https://github.com/flakeheaven/flakeheaven)
: Python linter with [lots of
    checks](https://lyz-code.github.io/blue-book/devops/flakeheaven#plugins).

[Black](https://black.readthedocs.io/en/stable/)
: Python formatter to keep a nice style without effort.

[Autoimport](https://lyz-code.github.io/autoimport)
: Python formatter to automatically fix wrong import statements.

[isort](https://github.com/timothycrosley/isort)
: Python formatter to order the import statements.

[PDM](https://pdm.fming.dev/)
: Command line tool to manage the dependencies.

[Mkdocs](https://www.mkdocs.org/)
: To build this documentation site, with the
[Material theme](https://squidfunk.github.io/mkdocs-material).

[Safety](https://github.com/pyupio/safety)
: To check the installed dependencies for known security vulnerabilities.

[Bandit](https://bandit.readthedocs.io/en/latest/)
: To finds common security issues in Python code.

[Yamlfix](https://github.com/lyz-code/yamlfix)
: YAML fixer.

# Contributing

For guidance on setting up a development environment, and how to make
a contribution to *pass-collaborate*, see [Contributing to
pass-collaborate](https://lyz-code.github.io/pass-collaborate/contributing).
