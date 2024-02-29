package health

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// @Tags Health
// @Description Check the status of the server
// @Success 200
// @Router /status [get]
func GetHealth(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}
