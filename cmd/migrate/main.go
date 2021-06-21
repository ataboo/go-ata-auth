package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ataboo/go-ata-auth/pkg/common"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"

	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var UserPath = []string{"psql", "user"}
var PasswordPath = []string{"psql", "pass"}

func main() {
	common.MustLoadEnv()

	rootAbsPath, _ := filepath.Abs(common.RootFilePath)
	migrationsPath := filepath.Join("file://", rootAbsPath, "migrations")

	up := flag.Bool("up", false, "run the up migrations")
	down := flag.Bool("down", false, "run the down migrations")
	force := flag.Int("force", 0, "force the migration to a specific version")
	flag.Parse()

	connectionStr := os.Getenv("DB_CONNECTION_STRING")

	db, err := sql.Open("postgres", connectionStr)
	if err != nil {
		log.Fatal(err)
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}

	m, err := migrate.NewWithDatabaseInstance(migrationsPath, "postgres", driver)
	if err != nil {
		log.Fatal(err)
	}

	if *up {
		fmt.Println("Running migration up...")
		err = m.Up()
		if err != nil {
			log.Fatal(err)
		}
	}

	if *down {
		fmt.Println("Running migration down...")
		err = m.Down()
		if err != nil {
			log.Fatal(err)
		}
	}

	if *force != 0 {
		fmt.Printf("Forcing migration to %d...\n", *force)
		err = m.Force(*force)
		if err != nil {
			log.Fatal(err)
		}
	}
}
