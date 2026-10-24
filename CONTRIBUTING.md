# Contributing

Thanks for improving VaultCore. Keep changes testable and backwards-conscious.

1. Open an issue describing the bug or behavior change and its affected operating systems.
2. Add focused unit or integration tests (especially for data integrity and filesystem safety).
3. Build with CMake and run `ctest --test-dir build --output-on-failure`.
4. Where possible, run sanitizers with `-DVAULTCORE_ENABLE_SANITIZERS=ON` on GCC/Clang.
5. Make sure the CLI help and docs describe all user-visible behavior and limitations.
6. Keep commits small and descriptive; don't submit vault contents, credentials, or backups.

## Style

- Target C++20. Prefer RAII, `std::filesystem`, value types, and explicit error handling.
- Use descriptive names; avoid fragile platform-specific behavior without OS-specific tests.
- Preserve existing format versions; never silently change the serialization layout.
- Do not introduce a cryptographic algorithm without published test vectors and review.
- Prefer zero runtime dependencies unless new capabilities clearly justify them.
