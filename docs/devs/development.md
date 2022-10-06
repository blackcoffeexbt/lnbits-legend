---
layout: default
title: For developers
nav_order: 4
has_children: true
---


For developers
==============

Thanks for contributing :)

Running LNbits with the reload flag enabled
====
```
poetry run uvicorn lnbits.__main__:app --host=0.0.0.0 --port=5000 --reload
```

Tests
=====

This project has unit tests that help prevent regressions. Before you can run the tests, you must install a few dependencies:
```bash
poetry install
npm i
```

Then to run the tests:
```bash
make test
```

Run formatting:
```bash
make format
```

Run mypy checks:
```bash
poetry run mypy
```

Run everything:
```bash
make all
```
