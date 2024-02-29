BIN = ./bin/auth
DIR = ./cmd

install:
	go install

build:
	go build -o ${BIN} ${DIR}

dev:
	go run ${DIR}

test:
	go test ${DIR}
