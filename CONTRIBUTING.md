# Contributing

Contributions are welcome when they preserve the project's passive, bounded design.

1. Open an issue describing the public data source or behavior.
2. Add a failing test before implementation.
3. Keep network operations time-bounded and response-size-bounded.
4. Do not add credential attacks, port scanning, access-control bypasses, stealth features, or private-network access.
5. Run `python3 -m unittest discover -s tests -v` before opening a pull request.

By contributing, you agree that your contribution is licensed under the MIT License.
