# Contributing to VaultSpectre

Thank you for your interest in contributing to VaultSpectre!

## Development Setup

1. **Prerequisites**
   - Go 1.21 or later
   - Git
   - Make
   - Access to a Vault instance for testing (optional, can use dev mode)

2. **Clone and Build**
   ```bash
   git clone https://github.com/ppiankov/vaultspectre.git
   cd vaultspectre
   make deps
   make build
   ```

3. **Run Tests**
   ```bash
   make test
   ```

4. **Format and Vet**
   ```bash
   make fmt
   make vet
   ```

## Project Structure

```
vaultspectre/
├── cmd/vaultspectre/      # CLI entry point
├── internal/              # Core implementation
│   ├── commands/         # Cobra commands
│   ├── scanner/          # Repository scanning logic
│   ├── vault/            # Vault client & validator
│   ├── analyzer/         # Result analysis
│   └── report/           # Report generation
├── examples/             # Example test repositories
├── Makefile
└── README.md
```

## How to Contribute

### Reporting Bugs

Open an issue with:
- VaultSpectre version (`vaultspectre version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Sample input files (if applicable)

### Suggesting Features

Open an issue describing:
- Use case
- Proposed solution
- Alternatives considered

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Run `make all` to ensure everything passes
6. Commit with clear messages
7. Push to your fork
8. Open a pull request

### PR Guidelines

- Keep changes focused and atomic
- Update documentation for new features
- Add tests for bug fixes and new functionality
- Follow existing code style
- Ensure `make all` passes

## Adding New Scanners

To add support for a new file type or pattern:

1. Add pattern to `internal/scanner/patterns.go`:
   ```go
   {
       Name:  "my_new_scanner",
       Type:  "file_type",
       Regex: regexp.MustCompile(`your-regex-here`),
   }
   ```

2. Add the file extension to `shouldScanFile()` in `internal/scanner/scanner.go`

3. Add test cases

4. Update README with supported file types

## Testing

### Unit Tests

```bash
make test
```

### Integration Tests

Test with a real Vault instance:

```bash
# Start Vault in dev mode
vault server -dev &

# Run integration tests
./test/integration-test.sh
```

### Manual Testing

Use the example repository:

```bash
make build
cd examples
../bin/vaultspectre scan --repo ./test-repo --vault-addr http://127.0.0.1:8200 --token root
```

## Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Run `go vet` before committing
- Keep functions small and focused
- Add comments for exported functions
- Use meaningful variable names

## Commit Messages

Follow conventional commits format:

```
type(scope): subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add support for Helm values files
fix(validator): handle KV v1 paths correctly
docs(readme): update installation instructions
```

## Release Process

1. Update version in `internal/commands/version.go`
2. Update CHANGELOG.md
3. Tag the release: `git tag -a v0.x.0 -m "Release v0.x.0"`
4. Push tag: `git push origin v0.x.0`
5. GitHub Actions will build and release

## Questions?

- Open an issue
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
