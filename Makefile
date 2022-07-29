.PHONY : test format build clean

ALL_PACKAGES=$(shell go list ./... | grep -v "vendor")

test:
	$(foreach pkg, $(ALL_PACKAGES),\
	go test -race -v $(pkg);)

test-cover:
	$(foreach pkg, $(ALL_PACKAGES),\
	go test -race -covermode=atomic -coverprofile=coverage.txt $(pkg);)

format:
	find . -name "*.go" -not -path "./vendor/*" -not -path ".git/*" | xargs gofmt -s -d -w

clean:
	@echo "cleaning unused file"
	rm -rf app \
	rm -rf webapp \
	&& rm -rf *.txt