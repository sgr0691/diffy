# Contributing to Diffy

Thanks for your interest in contributing!

## Getting started

```bash
git clone https://github.com/sgr0691/diffy
cd diffy
go build ./cmd/diffy
go test ./...
```

## Adding a rule

1. Add a sample plan JSON under `examples/plan/`
2. Add an expected output snapshot under `examples/expected/`
3. Write your rule in `internal/analyze/`
4. Run `go test ./...` and ensure all tests pass

## Submitting changes

- Fork the repo and create a feature branch
- Keep PRs small and focused
- Include tests for new rules

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
