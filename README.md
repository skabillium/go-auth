# Go Auth service

A personal project to get more familiar with REST APIs in Go. It is meant to handle some of the most
common patterns when creating a server:
 - Environment Variables
 - Swagger documentation
 - Versioning
 - Logging
 - Error handling
 - Database interfacing
 - Caching
 - File uploads
 - Email delivery

## Installation

1. Run `make install` to install all dependencies
2. Copy the `.env.example` file to a `.env` file and update with your specific values
3. Run `make build` to build the project
4. Run the `bin/auth` executable according to your operating system


### Docker

To create the postgres and redis instances needed for the server to run you can use the
`docker-compose.yaml`. Run `docker-compose up` after creating your `.env` file and they will
be initialized.

To create the schema for the database run the `cmd/db/schema.sql` file in postgres
