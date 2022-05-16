package jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/project-flogo/core/data"
	"github.com/project-flogo/core/data/coerce"
	"github.com/project-flogo/core/data/expression/function"
	"log"
	"strings"
	"time"
)

func init() {
	_ = function.Register(&fnGenerateToken{})
}

type fnGenerateToken struct {
}

func (s *fnGenerateToken) Name() string {
	return "generateToken"
}

func (fnGenerateToken) Sig() (paramTypes []data.Type, isVariadic bool) {
	return []data.Type{data.TypeString, data.TypeString, data.TypeString, data.TypeString, data.TypeInt}, false
}

func (fnGenerateToken) Eval(params ...interface{}) (interface{}, error) {
	privateKey, err := coerce.ToString(params[0])
	if err != nil {
		return nil, fmt.Errorf("audience input [%+v] must be string", params[0])
	}
	audience, err := coerce.ToString(params[1])
	if err != nil {
		return nil, fmt.Errorf("audience input [%+v] must be string", params[1])
	}
	issuer, err := coerce.ToString(params[2])
	if err != nil {
		return nil, fmt.Errorf("issuer input [%+v] must be string", params[2])
	}
	subject, err := coerce.ToString(params[3])
	if err != nil {
		return nil, fmt.Errorf("subject input [%+v] must be string", params[3])
	}
	expiry, err := coerce.ToInt(params[4])
	if err != nil {
		return nil, fmt.Errorf("expiry in seconds input [%+v] must be integer", params[4])
	}

	//Check if PrivateKey is linearized
	if !strings.Contains(privateKey, "\n") {
		privateKey = reconstructPrivateKey(privateKey)
	}

	var token string
	jwtToken := NewJWT([]byte(privateKey))
	// Create a new JWT token.
	token, err = jwtToken.Create(audience, issuer, subject, time.Second*time.Duration(expiry))
	if err != nil {
		log.Fatalln(err)
	}

	return token, nil
}

type JWT struct {
	privateKey []byte
}

func NewJWT(privateKey []byte) JWT {
	return JWT{
		privateKey: privateKey,
	}
}

func (j JWT) Create(aud string, iss string, sub string, ttl time.Duration) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		fmt.Sprintf("Failed parsing privateKey: %v", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["aud"] = aud                 // Audience.
	claims["iss"] = iss                 // issuer
	claims["sub"] = sub                 // subject
	claims["exp"] = now.Add(ttl).Unix() // expiry

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", err

	}

	return token, nil
}

func reconstructPrivateKey(linearPrivateKey string) string {
	beginString := strings.Split(linearPrivateKey, "-----BEGIN PRIVATE KEY----- ")
	endString := strings.Split(beginString[1], "-----END PRIVATE KEY-----")
	linearPrivateKey = "-----BEGIN PRIVATE KEY----- \n" + strings.Replace(endString[0], " ", "\n", -1) + "-----END PRIVATE KEY-----"
	return linearPrivateKey
}

func parseJWTToken(jwtToken string, privateKey string) *jwt.Token {
	//Check if PrivateKey is linearized
	if !strings.Contains(privateKey, "\n") {
		privateKey = reconstructPrivateKey(privateKey)
	}
	out, _ := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	return out
}
