# Contributing

Thanks for looking. Bug reports with a way to reproduce them are the most useful thing you can send.

## Build and test

Requirements: .NET SDK 10, Python 3 (for the end-to-end suites). On macOS the Xcode command line tools.

```bash
tests/run.sh                        # unit tests, warning-free Native AOT publish, both end-to-end suites
dotnet test tests/Hubris.Tests      # unit tests only
```

## What a change needs

- `tests/run.sh` passes. The publish step fails on any warning, including trim and AOT warnings.
- New logic comes with a test that fails without it: a unit test, or a check in `tests/e2e`.
- No reflection and no runtime code generation: the hub is Native AOT. JSON goes through the source-generated contexts.
- The README says what the code does. If behaviour changes, change the sentence that describes it.
- A security claim names its limit, in the code comment and in the README.

## Pull requests

One change per pull request, with a description of what was wrong or missing and how you checked the fix. For
anything larger than a bug fix, open an issue first so the direction can be agreed before you write it.

Security problems do not go into issues or pull requests: see [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is released under the project's MIT licence.
