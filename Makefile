BIN = ./bin/auth
DIR = ./cmd
DOCS_DIR = ${DIR}/docs

clean:
	rm -rf ${DOCS_DIR}

docs:
	swag init --dir ${DIR} --output ${DOCS_DIR}

templ:
	templ generate

install:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest 
	go install github.com/a-h/templ/cmd/templ@latest
	go install

build: clean docs
	go build -o ${BIN} ${DIR}

dev: docs
	go run ${DIR}

test:
	go test ${DIR}

queries:
	sqlc generate

pg:
	docker exec -it postgres psql -U auth_user -d auth_database
