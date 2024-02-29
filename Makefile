BIN = ./bin/auth
DIR = ./cmd

swagger:
	swag init --dir ${DIR} --output ${DIR}/docs

install:
	go install

build: swagger
	go build -o ${BIN} ${DIR}

dev:
	go run ${DIR}

test:
	go test ${DIR}
