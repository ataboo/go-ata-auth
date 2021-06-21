package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ataboo/go-ata-auth/pkg/models"
	"github.com/ataboo/go-ata-auth/pkg/testhelpers"
	"github.com/google/uuid"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

var testLock sync.Mutex

func TestLogin(t *testing.T) {
	testLock.Lock()
	defer testLock.Unlock()

	ctx := context.Background()

	db := testhelpers.InitTestDb(t, true)
	boil.SetDB(db)

	initServer()

	validUser := testing_createUser(t, db, "Valid User", "found@email.com", true)
	inactiveUser := testing_createUser(t, db, "Inactive User", "inactive@email.com", false)

	//====== Rejected when email not found ==========
	g, response := testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/login", LoginData{
		Email:    "notfound@email.com",
		Password: "password",
	})

	handleLogin(g)

	if response.Code != http.StatusUnauthorized {
		t.Error("expected unauthorized")
	}

	if response.Body.Len() > 0 {
		t.Error("expected empty response body")
	}

	if n, err := models.Sessions().Count(ctx, db); err != nil || n > 0 {
		t.Error("failed to confirm no sessions created")
	}

	//====== Rejected when password doesn't match ==========
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/login", LoginData{
		Email:    validUser.Email,
		Password: "notrightpassword",
	})

	handleLogin(g)

	if response.Code != http.StatusUnauthorized {
		t.Error("expected unauthorized")
	}

	if response.Body.Len() > 0 {
		t.Error("expected empty response body")
	}

	if n, err := models.Sessions().Count(ctx, db); err != nil || n > 0 {
		t.Error("failed to confirm no sessions created")
	}

	//====== Rejected when user inactive ==========
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/login", LoginData{
		Email:    inactiveUser.Email,
		Password: "password",
	})

	handleLogin(g)

	if response.Code != http.StatusUnauthorized {
		t.Error("expected unauthorized")
	}

	if response.Body.Len() > 0 {
		t.Error("expected empty response body")
	}

	if n, err := models.Sessions().Count(ctx, db); err != nil || n > 0 {
		t.Error("failed to confirm no sessions created")
	}

	//====== Successful login ==========
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/login", LoginData{
		Email:    validUser.Email,
		Password: "password",
	})

	handleLogin(g)

	if response.Code != http.StatusOK {
		t.Error("expected ok response")
	}

	responseSession := SessionResponseData{}
	if err := json.Unmarshal(response.Body.Bytes(), &responseSession); err != nil {
		t.Error(err)
	}

	dbSession, err := models.Sessions(qm.Where("user_id = ?", validUser.ID)).One(ctx, db)
	if err != nil {
		t.Error(err)
	}

	if dbSession.AccessToken != responseSession.AccessToken {
		t.Error("unnexpected access token")
	}

	if dbSession.RefreshToken != responseSession.RefreshToken {
		t.Error("unnexpected refresh token")
	}

	parseDb := time.Unix(dbSession.ExpiresAt.Unix(), 0)
	parseSession := time.Unix(responseSession.ExpiresAt, 0)
	fmt.Println(parseDb.Format("Jan 2 15:04:05 -0700"))
	fmt.Println(parseSession.Format("Jan 2 15:04:05 -0700"))

	if dbSession.ExpiresAt.Unix() != responseSession.ExpiresAt {
		t.Error("unnexpected expires at")
	}

	if dbSession.ExpiresAt.Sub(dbSession.CreatedAt)-sessionLifetime > time.Minute {
		t.Error("expiration out of expected range", dbSession.ExpiresAt.Unix(), dbSession.CreatedAt, sessionLifetime)
	}

	if dbSession.AccessToken != responseSession.AccessToken {
		t.Error("expected access token to match")
	}

	if dbSession.RefreshToken != responseSession.RefreshToken {
		t.Error("expected access token to match")
	}

	if responseSession.Email != "found@email.com" {
		t.Error("expected email to match")
	}
}

func TestLogout(t *testing.T) {
	testLock.Lock()
	defer testLock.Unlock()

	ctx := context.Background()

	db := testhelpers.InitTestDb(t, true)
	boil.SetDB(db)

	initServer()

	validUser := testing_createUser(t, db, "Valid User", "found@email.com", true)

	session := testing_createSession(t, ctx, db, validUser.ID)

	//====== Rejected when token not found ==========
	wrongToken, err := generateUniqueToken(ctx, db)
	if err != nil {
		t.Error(err)
	}

	g, response := testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/logout", LogoutData{
		AccessToken: wrongToken,
	})

	handleLogout(g)

	if response.Code != http.StatusNotFound {
		t.Error("expected unauthorized", response.Code)
	}

	if response.Body.Len() > 0 {
		t.Error("expected empty response body")
	}

	dbSession, err := models.FindSession(ctx, db, session.ID)
	if err != nil {
		t.Error("failed to confirm session not closed")
	}

	if dbSession.EndedAt.Valid {
		t.Error("end for session should be null")
	}

	//====== Successful Logout  ==========
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/logout", LogoutData{
		AccessToken: session.AccessToken,
	})

	handleLogout(g)

	if response.Code != http.StatusOK {
		t.Error("expected status okay", response.Code)
	}

	dbSession, err = models.FindSession(ctx, db, session.ID)
	if err != nil {
		t.Error("failed to confirm session closed")
	}

	if !dbSession.EndedAt.Valid {
		t.Error("session should be closed")
	}

	//====== Failed Double Logout  ==========
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/logout", LogoutData{
		AccessToken: session.AccessToken,
	})

	handleLogout(g)

	if response.Code != http.StatusNotFound {
		t.Error("expected status not found", response.Code)
	}

	dbSession, err = models.FindSession(ctx, db, session.ID)
	if err != nil {
		t.Error("failed to confirm session closed")
	}

	if !dbSession.EndedAt.Valid {
		t.Error("session should be closed")
	}
}

func testing_createUser(t *testing.T, db *sql.DB, name string, email string, active bool) *models.User {
	user := &models.User{
		ID:     uuid.NewString(),
		Name:   name,
		Email:  email,
		Active: active,
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Error(err)
	}
	user.Hashword = hashedPassword

	if err := user.Insert(context.Background(), db, boil.Infer()); err != nil {
		t.Error(err)
	}

	return user
}

func testing_createSession(t *testing.T, ctx context.Context, db *sql.DB, userId string) *models.Session {
	accessToken, err := generateUniqueToken(ctx, db)
	if err != nil {
		t.Error(err)
	}

	refreshToken, err := generateUniqueToken(ctx, db)
	if err != nil {
		t.Error(err)
	}

	newSession := &models.Session{
		ID:           uuid.NewString(),
		UserID:       userId,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	if err := newSession.Insert(context.Background(), db, boil.Infer()); err != nil {
		t.Error(err)
	}

	return newSession
}
