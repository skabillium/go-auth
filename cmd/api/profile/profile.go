package profile

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"skabillium.io/auth-service/cmd/api/auth"
	"skabillium.io/auth-service/cmd/db"
)

const UploadsDir = "uploads"

var (
	queries *db.Queries
	ctx     = context.Background()
)

func dirExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}

	return true

}

func InitProfileHandlers(g *echo.Group, q *db.Queries) {
	queries = q
	IsLoggedIn := echojwt.JWT([]byte(os.Getenv("JWT_SECRET")))

	// Initialize uploads directory if not present
	if !dirExists(UploadsDir) {
		err := os.Mkdir(UploadsDir, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}

	g.PATCH("/profile/picture", UpdateProfilePicture, IsLoggedIn)
}

type UploadedFile struct {
	name string
	path string
}

func CopyToUploads(file *multipart.FileHeader) (*UploadedFile, error) {
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()

	splitted := strings.Split(file.Filename, ".")
	ext := splitted[len(splitted)-1]
	name := strconv.Itoa(int(time.Now().Unix())) + "-" + auth.GenerateRandomString(10)
	fullname := name + "." + ext
	fullpath := path.Join(UploadsDir, fullname)

	dst, err := os.Create(fullpath)
	if err != nil {
		return nil, err
	}
	defer dst.Close()

	if _, err = io.Copy(dst, src); err != nil {
		return nil, err
	}

	return &UploadedFile{name: fullname, path: fullpath}, nil
}

// @Tags Profile
// @Description Register a new user
// @Security BearerAuth
// @Success 204
// @Error 400
// @Error 500
// @Accept multipart/form-data
// @Param profilePicture formData file true "Profile picture file"
// @Router /profile/picture [PATCH]
func UpdateProfilePicture(c echo.Context) error {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		fmt.Println(c.Request().Header.Get("Authorization"))
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while fetching token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching claims")
	}

	userIdStr, ok := claims["id"].(string)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while getting id from token")
	}

	userUuid, err := uuid.Parse(userIdStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while parsing id")
	}

	AllowedContentTypes := []string{"image/png", "image/jpeg"}

	file, err := c.FormFile("profilePicture")
	if err != nil {
		return err
	}

	// Handle unsupported content type
	filetype := file.Header.Get("Content-Type")
	if slices.Index(AllowedContentTypes, filetype) == -1 {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Unsupported media type "+filetype)
	}

	uploaded, err := CopyToUploads(file)
	if err != nil {
		return err
	}

	imageUrl := os.Getenv("SERVER_URL") + "/uploads/" + uploaded.name
	err = queries.UpdateUserProfilePictureById(ctx, db.UpdateUserProfilePictureByIdParams{
		ID:             pgtype.UUID{Bytes: userUuid, Valid: true},
		ProfilePicture: pgtype.Text{String: imageUrl, Valid: true},
	})
	if err != nil {
		os.Remove(uploaded.path)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while saving picture")
	}

	return c.NoContent(http.StatusNoContent)
}
