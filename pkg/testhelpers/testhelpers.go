package testhelpers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/ataboo/go-ata-auth/pkg/common"
	"github.com/ataboo/go-ata-auth/pkg/dbcontext"
	"github.com/ataboo/go-ata-auth/pkg/models"
	"github.com/gin-gonic/gin"
)

var TestDBLock sync.Mutex

func NewGinTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	return c, recorder
}

func InitTestDb(t *testing.T, fresh bool) *sql.DB {
	common.MustLoadEnv()
	db, err := sql.Open("postgres", os.Getenv(common.EnvDbTestConnectionString))
	if err != nil {
		t.Error(err)
		return nil
	}

	if err := dbcontext.MigrateDB(db); err != nil {
		t.Error(err)
	}

	if fresh {
		if _, err := models.Sessions().DeleteAll(context.Background(), db); err != nil {
			t.Error(err)
		}

		if _, err := models.Users().DeleteAll(context.Background(), db); err != nil {
			t.Error(err)
		}
	}

	return db
}

func SetTestJsonPostRequest(g *gin.Context, url string, data interface{}) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	g.Request, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	g.Request.Header.Set("Content-Type", "application/json")

	return nil
}
