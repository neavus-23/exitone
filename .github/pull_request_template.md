## Summary

<!-- What changed, and why. Link an issue if there is one. -->

## Test plan

<!-- How was this verified? `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...` -->
- [ ] `go build ./...`
- [ ] `go vet ./...`
- [ ] `gofmt -l .` is empty
- [ ] `go test ./...`

## Checklist

- [ ] No secrets, real credentials, or real target data (IPs, hostnames, hashes) in the diff — including in comments and test fixtures.
- [ ] Any new exported identifier has a doc comment.
- [ ] Any change to command behavior is reflected in `README.md` and, if applicable, `man/exitone.1`.
