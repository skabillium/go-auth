BIN = ./bin/auth
DIR = ./cmd
DOCS_DIR = ${DIR}/docs

clean:
	rm -rf ${DOCS_DIR}

swagger:
	swag init --dir ${DIR} --output ${DOCS_DIR}

install:
	go install
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest 

build: clean swagger
	go build -o ${BIN} ${DIR}

dev: swagger
	go run ${DIR}

test:
	go test ${DIR}

queries:
	sqlc generate

pg:
	docker exec -it postgres psql -U auth_user -d auth_database
