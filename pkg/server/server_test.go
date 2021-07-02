package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ataboo/go-ata-auth/pkg/models"
	"github.com/ataboo/go-ata-auth/pkg/testhelpers"
	"github.com/google/uuid"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

func TestLogin(t *testing.T) {
	testhelpers.TestDBLock.Lock()
	defer testhelpers.TestDBLock.Unlock()

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

	//TODO inactive can't login
}

func TestLogout(t *testing.T) {
	testhelpers.TestDBLock.Lock()
	defer testhelpers.TestDBLock.Unlock()

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

func TestPasswordValidation(t *testing.T) {
	validation := newValidationBag()

	shortPassword := strings.Repeat("p", PasswordLengthMin-1)
	longPassword := strings.Repeat("p", PasswordLengthMax+1)

	validatePassword(validation, shortPassword, shortPassword)
	if _, ok := validation.Responses["password"]; !ok {
		t.Error("expected password error")
	}

	validation.Clear()
	validatePassword(validation, longPassword, longPassword)
	if _, ok := validation.Responses["password"]; !ok {
		t.Error("expected password error")
	}

	okPassword1 := strings.Repeat("p", PasswordLengthMin)
	okPassword2 := strings.Repeat("p", PasswordLengthMax)

	validation.Clear()
	validatePassword(validation, okPassword1, okPassword1)
	if _, ok := validation.Responses["password"]; ok {
		t.Error("expected no error")
	}

	validation.Clear()
	validatePassword(validation, okPassword2, okPassword2)
	if _, ok := validation.Responses["password"]; ok {
		t.Error("expected no error")
	}
}

func TestPasswordConfirmValidation(t *testing.T) {
	validation := newValidationBag()

	validatePassword(validation, "password", "no_match")
	if _, ok := validation.Responses["confirm_password"]; !ok {
		t.Error("expected error")
	}

	validation.Clear()
	validatePassword(validation, "password", "password")
	if _, ok := validation.Responses["confirm_password"]; ok {
		t.Error("expected no error")
	}
}

func TestDisplayNameValidation(t *testing.T) {
	validation := newValidationBag()
	tooShort := strings.Repeat("d", StringLengthMin-1)
	tooLong := strings.Repeat("d", StringLengthMax+1)
	good1 := strings.Repeat("d", StringLengthMin)
	good2 := strings.Repeat("d", StringLengthMax)

	validateDisplayName(validation, tooShort)
	if _, ok := validation.Responses["display_name"]; !ok {
		t.Error("expected error")
	}

	validation.Clear()
	validateDisplayName(validation, tooLong)
	if _, ok := validation.Responses["display_name"]; !ok {
		t.Error("expected error")
	}

	validation.Clear()
	validateDisplayName(validation, good1)
	if _, ok := validation.Responses["display_name"]; ok {
		t.Error("expected no error")
	}

	validation.Clear()
	validateDisplayName(validation, good2)
	if _, ok := validation.Responses["display_name"]; ok {
		t.Error("expected no error")
	}
}

func TestCreateUser(t *testing.T) {
	testhelpers.TestDBLock.Lock()
	defer testhelpers.TestDBLock.Unlock()

	ctx := context.Background()

	db := testhelpers.InitTestDb(t, true)
	boil.SetDB(db)

	initServer()

	//====== Rejected when fields invalid ==========
	g, response := testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/create", CreateUserData{
		Email:           "notanemail",
		DisplayName:     "",
		Password:        "",
		ConfirmPassword: "2",
	})

	handleCreateUser(g)

	testing_assertUserCreateFail(t, db, response, ctx, []string{"email", "display_name", "password", "confirm_password"})

	//====== Rejected when json bad ==========
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/create", "bad json")
	handleCreateUser(g)

	if response.Code != http.StatusBadRequest {
		t.Error("unnexpected response code", response.Code)
	}

	//====== Rejected when email already taken ==========
	existingUser := models.User{
		ID:       uuid.NewString(),
		Name:     "Existing User",
		Email:    "existing@email.com",
		Hashword: []byte("notahash"),
		Active:   false,
	}
	if err := existingUser.Insert(ctx, db, boil.Infer()); err != nil {
		t.Error(err)
	}

	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/create", CreateUserData{
		Email:           "existing@email.com",
		DisplayName:     "New User",
		Password:        "password",
		ConfirmPassword: "password",
	})

	handleCreateUser(g)

	testing_assertUserCreateFail(t, db, response, ctx, []string{"email"})

	//====== Successfully created new user ==========
	createData := CreateUserData{
		Email:           "newuser@email.com",
		DisplayName:     "New User",
		Password:        "password",
		ConfirmPassword: "password",
	}

	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/create", createData)

	handleCreateUser(g)

	if response.Code != http.StatusOK {
		t.Error("expected ok response")
	}

	createdUser, err := models.Users(qm.Where("email = ?", "newuser@email.com")).One(ctx, db)
	if err != nil {
		t.Error(err)
	}

	if createdUser.Email != createData.Email {
		t.Error("unnexpected email: ", createdUser.Email)
	}

	if !createdUser.Active {
		t.Error("expected user to be active")
	}

	if err := bcrypt.CompareHashAndPassword(createdUser.Hashword, []byte(createData.Password)); err != nil {
		t.Error("password doesn't match hash")
	}

	if createdUser.Name != createData.DisplayName {
		t.Error("expected matching names")
	}
}

func TestRefresh(t *testing.T) {
	testhelpers.TestDBLock.Lock()
	defer testhelpers.TestDBLock.Unlock()

	ctx := context.Background()

	db := testhelpers.InitTestDb(t, true)
	boil.SetDB(db)

	initServer()

	user := models.User{
		ID:       uuid.NewString(),
		Name:     "New User",
		Email:    "newuser@email.com",
		Hashword: []byte("wouldbehashed"),
		Active:   false,
	}
	if err := user.Insert(ctx, db, boil.Infer()); err != nil {
		t.Error(err)
	}

	oldSession := models.Session{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		AccessToken:  "accesstoken",
		RefreshToken: "refreshtoken",
		EndedAt:      null.Time{Valid: false},
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := oldSession.Insert(ctx, db, boil.Infer()); err != nil {
		t.Error(err)
	}

	//====== Rejected when token not found ==========
	g, response := testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/refresh", RefreshData{
		RefreshToken: "doesnt_exist",
	})

	handleRefresh(g)

	if response.Code != http.StatusNotFound {
		t.Error("expected not found status", response.Code)
	}

	if err := oldSession.Reload(ctx, db); err != nil {
		t.Error(err)
	}

	if oldSession.EndedAt.Valid {
		t.Error("expected old session not ended")
	}

	if _, err := models.Sessions(qm.Where("id != ?", oldSession.ID)).One(ctx, db); err == nil {
		t.Error("expected session error")
	}

	// Rejected when user inactive
	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/refresh", RefreshData{
		RefreshToken: "refreshtoken",
	})

	handleRefresh(g)

	if response.Code != http.StatusForbidden {
		t.Error("expected forbidden", response.Code)
	}

	if err := oldSession.Reload(ctx, db); err != nil {
		t.Error(err)
	}

	if !oldSession.EndedAt.Valid {
		t.Error("expected old session to be ended")
	}

	if _, err := models.Sessions(qm.Where("ended_at IS NULL")).One(ctx, db); err == nil {
		t.Error("expected no open sessions")
	}

	//Rejected when old session expired
	oldSession.EndedAt = null.NewTime(time.Time{}, false)
	oldSession.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := oldSession.Update(ctx, db, boil.Infer()); err != nil {
		t.Error(err)
	}

	user.Active = true
	if _, err := user.Update(ctx, db, boil.Infer()); err != nil {
		t.Error(err)
	}

	g, response = testhelpers.NewGinTestContext()
	testhelpers.SetTestJsonPostRequest(g, "api/v1/refresh", RefreshData{
		RefreshToken: "refreshtoken",
	})

	handleRefresh(g)

	if response.Code != http.StatusNotFound {
		t.Error("expected not found", response.Code)
	}

}

func testing_assertUserCreateFail(t *testing.T, db *sql.DB, res *httptest.ResponseRecorder, ctx context.Context, failedFields []string) ValidationBag {
	if res.Code != http.StatusBadRequest {
		t.Errorf("expected unauthorized instead of '%d'", res.Code)
	}

	responseValidation := ValidationBag{}
	if err := json.Unmarshal(res.Body.Bytes(), &responseValidation); err != nil {
		t.Error(err)
	}
	if responseValidation.Valid() {
		t.Error("expected invalid response bag")
	}

	if n, err := models.Sessions().Count(ctx, db); err != nil || n > 0 {
		t.Error("failed to confirm no sessions created")
	}

	for _, field := range failedFields {
		if _, ok := responseValidation.Responses[field]; !ok {
			t.Errorf("expected %s validation message", field)
		}
	}

	return responseValidation
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
