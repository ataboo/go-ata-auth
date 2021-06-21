package common

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/joho/godotenv"
)

const (
	EnvServerHostname         = "SERVER_HOSTNAME"
	EnvDbConnectionString     = "DB_CONNECTION_STRING"
	EnvDbTestConnectionString = "DB_TEST_CONNECTION_STRING"
	EnvSessionLifetimeMins    = "SESSION_LIFETIME_MINS"
)

var (
	_, b, _, _ = runtime.Caller(0)

	// Root folder of this project
	RootFilePath = filepath.Join(filepath.Dir(b), "../..")
)

func LoadEnv() error {
	return godotenv.Load(filepath.Join(RootFilePath, ".env"))
}

func MustLoadEnv() {
	if err := LoadEnv(); err != nil {
		log.Fatal(err)
	}

	assertEnvVarsSet()
}

func assertEnvVarsSet() {
	allVars := []string{
		EnvServerHostname,
		EnvDbConnectionString,
		EnvSessionLifetimeMins,
	}

	fail := false

	for _, envVar := range allVars {
		if os.Getenv(envVar) == "" {
			fmt.Println("*** Environment var '" + envVar + "' must be set ***")
			fail = true
		}
	}

	if fail {
		log.Fatal("Some required env vars missing! Copy `.env.example` to `.env` and fill in the values.")
	}
}
