package utiltest

import (
	"github.com/dwahyudi/go-jwt-sample/internal/jwtsample/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSimpleSignAndValidate(t *testing.T) {
	var userId = 3
	var tokenString = util.JwtBuildAndSignJSON(userId)

	var validatedUserId, err = util.JwtValidate(tokenString)
	assert.Equal(t, 3, validatedUserId)
	assert.Nil(t, err)
}

func TestSimpleSignAndValidateWithStandardClaims(t *testing.T) {
	var userId = 3
	var tokenString = util.JwtBuildAndSignWithStandardClaims(userId)

	var validatedUserId, _ = util.JwtValidate(tokenString)
	assert.Equal(t, 3, validatedUserId)
}

func TestValidateWithNoneAlgorithm(t *testing.T) {
	// Base64-encoded of "none" algorithm JOSE header.
	var tokenString = "ewogICJhbGciOiAibm9uZSIsCiAgInR5cCI6ICJKV1QiCn0=.ewogICJ1c2VySWQiOiAzLAogICJhdWQiOiAic2FtcGxlLWF1ZGllbmNlIiwKICAiZXhwIjogMTU5Mzg2MTI4NiwKICAiaWF0IjogMTU5Mzg2MDM4NiwKICAiaXNzIjogInNhbXBsZS1pc3N1ZXIiLAogICJzdWIiOiAic2FtcGxlLXVzZXJuYW1lIgp9."

	var validatedUserId, err = util.JwtValidate(tokenString)
	assert.Equal(t, "Unexpected signing method: none", err.Error())
	assert.Equal(t, 0, validatedUserId)
}

func TestValidateMalformedJWT(t *testing.T) {
	var tokenString = "ewogICJhbGciOiAibm9uZSIsCiAgInR5cCI6ICJKV1QiCn0=."

	var validatedUserId, err = util.JwtValidate(tokenString)
	assert.Equal(t, "token contains an invalid number of segments", err.Error())
	assert.Equal(t, 0, validatedUserId)
}

func TestValidateWithDifferentSecret(t *testing.T) {
	var userId = 3
	var tokenString = util.JwtBuildAndSignJSONAnotherSecret(userId)

	var validatedUserId, err = util.JwtValidate(tokenString)
	assert.Equal(t, 0, validatedUserId)
	assert.Equal(t, "signature is invalid", err.Error())
}
