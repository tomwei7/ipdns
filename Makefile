SRC=$(shell find . -name "*.go")

all: bin/ipdns

bin/ipdns: $(SRC)
	CGO_ENABLED=0 GOOS=linux go build -o bin/ipdns .

.PHONY: all
