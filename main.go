package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"go-auth0-sample/platform/authenticator"
)

// e.GET("/users/:id", getUser)
func getUser(c echo.Context) error {
	sess, _ := session.Get("session", c)
	profile := sess.Values["profile"]

	return c.Render(http.StatusOK, "user.html", profile)
}

// login user and return jwt
func login(auth *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		state, err := generateRandomState()
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return nil
		}

		// Save the state inside the session.
		sess, _ := session.Get("session", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
		}
		fmt.Println("value of state:" + state)
		sess.Values["state"] = state
		sess.Save(c.Request(), c.Response())

		return c.Redirect(http.StatusTemporaryRedirect, auth.AuthCodeURL(state))
	}

}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}

// create user in the system
func callback(auth *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		stateFromSession := sess.Values["state"].(string)
		fmt.Println("value of state from session: " + stateFromSession)
		stateFromCallback := c.QueryParam("state")
		fmt.Println("value of state from callback: " + stateFromCallback)
		if stateFromCallback != stateFromSession {
			c.String(http.StatusBadRequest, "Invalid state parameter.")
			return nil
		}

		// Exchange an authorization code for a token.
		code := c.QueryParam("code")
		token, err := auth.Exchange(c.Request().Context(), code)
		if err != nil {
			c.String(http.StatusUnauthorized, "Failed to convert an authorization code into a token.")
			return nil
		}

		idToken, err := auth.VerifyIDToken(c.Request().Context(), token)
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to verify ID Token.")
			return nil
		}

		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return nil
		}

		sess.Values["access_token"] = token.AccessToken
		sess.Values["profile"] = profile
		sess.Save(c.Request(), c.Response())

		// Redirect to logged in page.
		return c.Redirect(http.StatusTemporaryRedirect, "/user")
	}
}

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {

	// Add global methods if data is a map
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	e := echo.New()

	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Create a new route group
	//apiGroup := e.Group("/api")

	// Use the custom middleware for routes within the /api group
	//apiGroup.Use(middleware.IsAuthenticated)

	e.Use(middleware.Logger())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	e.Static("/public", "static")
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("template/*.html")),
	}
	e.Renderer = renderer

	e.GET("/", func(c echo.Context) error {
		//return c.String(http.StatusOK, "Hello, World!, I did it!!")
		return c.Render(http.StatusOK, "home.html", nil)
	})

	//e.PUT("/users/:id", updateUser)
	//e.DELETE("/users/:id", deleteUser)
	auth, err := authenticator.New()
	if err != nil {
		log.Fatalf("Failed to initialize the authenticator: %v", err)
	}
	e.GET("/login", login(auth))
	e.GET("/callback", callback(auth))
	//e.POST("/users", saveUser)
	e.GET("/user", getUser)

	e.Logger.Fatal(e.Start(":3000"))
}
