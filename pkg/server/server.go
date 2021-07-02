package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	crypto_rand "crypto/rand"

	"github.com/ataboo/go-ata-auth/pkg/common"
	"github.com/ataboo/go-ata-auth/pkg/dbcontext"
	"github.com/ataboo/go-ata-auth/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"golang.org/x/crypto/bcrypt"
)

const TokenByteLength = 24
const TokenHexLength = TokenByteLength * 4 / 3

var sessionLifetime time.Duration = 0

func StartServer() error {
	if err := initServer(); err != nil {
		return err
	}

	router := gin.Default()
	router.GET("/", func(c *gin.Context) {
		c.String(200, "goataauth")
	})

	apiGroup := router.Group("api/v1")
	apiGroup.POST("create", handleCreateUser)
	apiGroup.POST("login", handleLogin)
	apiGroup.POST("logout", handleLogout)
	apiGroup.POST("refresh", handleRefresh)

	router.Run(os.Getenv(common.EnvServerHostname))

	return nil
}

func initServer() error {
	expirationMins, err := strconv.ParseInt(os.Getenv(common.EnvSessionLifetimeMins), 10, 32)
	if err != nil {
		return errors.New("failed to parse configured session lifetime")
	}
	sessionLifetime = time.Minute * time.Duration(expirationMins)

	return nil
}

func handleCreateUser(g *gin.Context) {
	data := CreateUserData{}
	if err := g.BindJSON(&data); err != nil {
		g.AbortWithStatus(http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	tx, err := dbcontext.NewDbTx(ctx)

	validation := newValidationBag()

	validation.Responses["email"] = validateEmail(data.Email)

	_, err = models.Users(qm.Where("email = ?", data.Email)).One(ctx, tx)
	if err == nil {
		validation.Responses["email"] = "this email has already been registered"
	}

	validateDisplayName(validation, data.DisplayName)
	validatePassword(validation, data.Password, data.ConfirmPassword)

	if !validation.Valid() {
		g.JSON(http.StatusBadRequest, validation)
		return
	}

	hashWord, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to hash password"))
		return
	}

	newUser := models.User{
		ID:       uuid.NewString(),
		Name:     data.DisplayName,
		Email:    data.Email,
		Hashword: []byte(hashWord),
		Active:   true,
	}
	err = newUser.Insert(ctx, tx, boil.Infer())

	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to save new user"))
		return
	}

	if tx.Commit() != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to commit new user"))
		return
	}

	g.JSON(http.StatusOK, "success")
}

func handleRefresh(g *gin.Context) {
	data := RefreshData{}
	if err := g.BindJSON(&data); err != nil {
		g.AbortWithStatus(http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	tx, err := dbcontext.NewDbTx(ctx)

	oldSession, err := models.Sessions(qm.Where("refresh_token = ? AND ended_at IS NULL", data.RefreshToken), qm.Load("User")).One(ctx, tx)
	if err != nil {
		g.AbortWithStatus(http.StatusNotFound)
		return
	}

	oldSession.EndedAt = null.TimeFrom(time.Now())
	if _, err := oldSession.Update(ctx, tx, boil.Infer()); err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to end session on refresh"))
		return
	}

	if !oldSession.R.User.Active {
		tx.Commit()
		g.AbortWithStatus(http.StatusForbidden)
		return
	}

	newSession := startNewSession(g, oldSession.R.User, ctx, tx)
	if newSession == nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to create new session"))
		return
	}

	if tx.Commit() != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to commit transaction"))
		return
	}

	response := SessionResponseData{
		AccessToken:  newSession.AccessToken,
		RefreshToken: newSession.RefreshToken,
		Email:        newSession.R.User.Email,
		ExpiresAt:    newSession.ExpiresAt.Unix(),
	}

	g.JSON(http.StatusOK, response)
}

func handleLogout(g *gin.Context) {
	data := LogoutData{}
	if err := g.BindJSON(&data); err != nil {
		g.AbortWithStatus(http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	tx, err := dbcontext.NewDbTx(ctx)

	session, err := models.Sessions(qm.Where("access_token = ? AND ended_at IS NULL", data.AccessToken)).One(ctx, tx)
	if err != nil {
		g.AbortWithStatus(http.StatusNotFound)
		return
	}

	session.EndedAt = null.TimeFrom(time.Now())
	if _, err := session.Update(ctx, tx, boil.Infer()); err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to save closed session"))
		return
	}

	if tx.Commit() != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to commit transaction"))
		return
	}

	g.JSON(http.StatusOK, "success")
}

func handleLogin(g *gin.Context) {
	data := LoginData{}
	if err := g.BindJSON(&data); err != nil {
		g.AbortWithStatus(http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	tx, err := dbcontext.NewDbTx(ctx)
	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to create db transaction"))
		return
	}

	user, err := models.Users(qm.Where("email = ?", data.Email)).One(ctx, tx)
	if err != nil {
		g.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !user.Active {
		g.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword(user.Hashword, []byte(data.Password)); err != nil {
		g.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to parse configured expiration"))
		return
	}

	openSessions, err := models.Sessions(qm.Where("user_id = ? AND ended_at IS NULL", user.ID)).All(ctx, tx)
	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to query open sessions"))
		return
	}

	_, err = openSessions.UpdateAll(ctx, tx, models.M{"ended_at": time.Now()})
	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to close old sessions"))
		return
	}

	session := startNewSession(g, user, ctx, tx)
	if session == nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to store new session"))
		return
	}

	response := SessionResponseData{
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		Email:        user.Email,
		ExpiresAt:    session.ExpiresAt.Unix(),
	}

	if tx.Commit() != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to commit transaction"))
		return
	}

	g.JSON(http.StatusOK, response)
}

func generateUniqueToken(ctx context.Context, db boil.ContextExecutor) (string, error) {
	for try := 0; try < 10; try++ {
		b := make([]byte, TokenByteLength)
		if _, err := crypto_rand.Read(b); err != nil {
			return "", err
		}

		token := base64.StdEncoding.EncodeToString(b)

		n, err := models.Sessions(qm.Where("access_token = ? OR refresh_token = ?", token, token)).Count(ctx, db)
		if err != nil {
			return "", err
		}

		if n == 0 {
			return token, nil
		}
	}

	return "", errors.New("failed to generate unique token")
}

func startNewSession(g *gin.Context, user *models.User, ctx context.Context, db *sql.Tx) *models.Session {
	accessToken, err := generateUniqueToken(ctx, db)
	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to generate access token"))
		return nil
	}

	refreshToken, err := generateUniqueToken(ctx, db)
	if err != nil {
		g.AbortWithError(http.StatusInternalServerError, errors.New("failed to generate refresh token"))
		return nil
	}

	session := models.Session{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(sessionLifetime),
	}

	if session.Insert(ctx, db, boil.Infer()) != nil {
		return nil
	}

	return &session
}
