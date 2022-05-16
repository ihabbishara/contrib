package jwtbuilder

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/project-flogo/core/activity"
	"log"
	"time"
)

type Activity struct{}

// init Flogo activity
func init() {
	_ = activity.Register(&Activity{})
}

var metadata = activity.ToMetadata(&Input{}, &Output{})

// Metadata for the Activity
func (ac *Activity) Metadata() *activity.Metadata {
	return metadata
}

func (ac *Activity) Eval(ctx activity.Context) (bool, error) {
	ctx.Logger().Debugf("Activity [%s] JWTBuilder", ctx.Name())

	input := &Input{}
	var err = ctx.GetInputObject(input)
	if err != nil {
		return false, activity.NewError(fmt.Sprintf("Activity [%s] Can't get input JSON object - %s", ctx.Name(), err.Error()), "JWTBuilder-01", nil)
	}

	var out string
	jwtToken := NewJWT([]byte(input.PrivateKey))
	// Create a new JWT token.
	out, err = jwtToken.Create(input.Audience, input.Issuer, input.Subject, time.Minute*3)
	if err != nil {
		log.Fatalln(err)
	}
	ctx.Logger().Debugf("New JWTToken has been generated: %s", out)

	err = ctx.SetOutputObject(&Output{JWTToken: out})
	if err != nil {
		return false, activity.NewError(fmt.Sprintf("Activity [%s] Can't set output JWTToken string - %s", ctx.Name(), err.Error()), "JWTBuilder-02", nil)
	}

	ctx.Logger().Debugf("Activity [%s] JWTBuilder completed", ctx.Name())
	return true, nil
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
		activity.NewError(fmt.Sprintf("Failed parsing privateKey: %v", err), "JWTBuilder-03", nil)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["aud"] = aud                 // Audience.
	claims["iss"] = iss                 // issuer
	claims["sub"] = sub                 // subject
	claims["exp"] = now.Add(ttl).Unix() // expiry

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", activity.NewError(fmt.Sprintf("Failed singing Claims: %v", err), "JWTBuilder-04", nil)

	}

	return token, nil
}
