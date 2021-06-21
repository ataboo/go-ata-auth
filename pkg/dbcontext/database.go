package dbcontext

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ataboo/go-ata-auth/pkg/common"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/volatiletech/sqlboiler/v4/boil"

	// Comment prevents lint
	_ "github.com/lib/pq"

	// Comment prevents lint
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func InitBoilerDb() (*sql.DB, error) {
	db, err := sql.Open("postgres", os.Getenv(common.EnvDbConnectionString))
	if err != nil {
		return nil, err
	}

	boil.SetDB(db)

	return db, nil
}

func NewDbTx(ctx context.Context) (*sql.Tx, error) {
	return boil.BeginTx(ctx, nil)
}

func MigrateDB(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(filepath.Join("file://", common.RootFilePath, "migrations"), "postgres", driver)
	if err != nil {
		return err
	}

	err = m.Up()
	if err == nil {
		fmt.Println("Migrated DB")
	}

	if err == migrate.ErrNoChange {
		return nil
	}

	return err
}
