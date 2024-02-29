BIN = ./bin/auth
DIR = ./cmd

build:
	go build -o ${BIN} ${DIR}

dev:
	go run ${DIR}

test:
	go test ${DIR}
