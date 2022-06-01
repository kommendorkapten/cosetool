GO=CGO_ENABLED=0 go

.PHONY: coset
coset:
	$(GO) build -trimpath -o coset ./cmd/coset

test:
	$(GO) test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...
