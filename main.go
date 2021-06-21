package main

import (
	"log"

	"github.com/ataboo/go-ata-auth/pkg/common"
	"github.com/ataboo/go-ata-auth/pkg/dbcontext"
	"github.com/ataboo/go-ata-auth/pkg/server"
)

func main() {
	common.MustLoadEnv()

	db, err := dbcontext.InitBoilerDb()
	if err != nil {
		log.Fatal(err)
	}

	if err := dbcontext.MigrateDB(db); err != nil {
		log.Fatal(err)
	}

	server.StartServer()
}
