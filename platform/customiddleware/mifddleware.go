package middleware

import (
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// IsAuthenticated is a middleware that checks if
// the user has already been authenticated previously.
func IsAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		profile := sess.Values["profile"]
		if profile == nil {
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		} else {
			return next(c)
		}
	}
}
