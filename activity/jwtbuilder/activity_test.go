package jwtbuilder

import (
	"github.com/golang-jwt/jwt"
	"github.com/project-flogo/core/activity"
	"github.com/project-flogo/core/support/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

const issuer = "3MVG9OjW2TAjFKUvW_FK.xteDX5._vfl57Df0i6pFszXCaQNaZDHvCnUD5yJ8Lyk2aN5Q24KumNNv6M6AaFT9"
const audience = "https://test.salesforce.com"
const subject = "lp.ngi.tibco@leaseplan.com.lpdev"
const privateKey = "-----BEGIN PRIVATE KEY-----\n" +
	"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCtIjxVzkBMKPBS\n" +
	"1LtqqRQEFKzEr9lWMMvrwmLcqDMLYG0fKk7BHv1BgzmSfcR8dvXAbjqPIaIxS6Mh\n" +
	"AgERaIz4h6rPw2TUIKeaEKk8tEWn8BGbFRNe0pGjuT16VYbek+wPw8/anq0Y/mZ1\n" +
	"mlTonU6t04tZX4RFVOEQlIUrmX7//eDmpoC7jV8ROhpPYKof5iJAaXk+EcmAq1DE\n" +
	"DKymKLIt5B7zBwuY6mky6/c5f7Tp/HwVcpZ8ppmmkyd7cr9PzeEi3jz6455vgZrn\n" +
	"UovVXlNv/fU2VxlZoAqiPIddzEjDIopIuRZ1SZ8J2aCwiQys5Is6k2WEeUBCSqhJ\n" +
	"0VywFcEHAgMBAAECggEABRtGZk2ADf8DH55QrNOx2HD3q5F4OpeT3C9OlS2M2+AL\n" +
	"N+kai42rcJw7PXviKL2lf/iAV6ppS0Ts2dNiTq4jwkzWF+yuc6dG6j9ljnnOuCZX\n" +
	"jphvitNxIkAbdRlCshvw0YI4Bj2540vVn9BegsHpCS19JbSwhQ782G1ZBDEx0sEQ\n" +
	"kycmRH1EvxoXHbU/yoXVqcoFo4ug1frkC/wVJDfP0Y4XaiM00+8YR1tnKSGb92GR\n" +
	"Cj92QXT6/U11ptFl7WbHFJp6XQemPJe199Nr9TGSdl6coGWXALPw39voosM4T+4L\n" +
	"7wTCOn64exDo3PuA2cT0eGNflNsr40PzZ9aV4VzNIQKBgQD/c5eaKNio20IKJIDt\n" +
	"4AjK8jHqLiWWqoyyE0kJ5tt714BVbWfSmgxu9AIXwzrxeiGP3uwW5w4lCUsuKwka\n" +
	"FayqRHmKc2awIPZTxcCoVN1RuP2VQlgtPGpF2cnfdVJ7TSEkl1W1VrACImgokQew\n" +
	"fikQHLQM/hP6014q8XxsuMwR9wKBgQCtgWXbGVKta8KHpusw9NKWyuGu5359lSEh\n" +
	"86Cn31uCtG6EwcxjW1FvIKCzBmPfg8hTZ9uWo5pAIcpuFiJLufhcKlaH8yhEwYGJ\n" +
	"JVviGJp65u8GsI6QKhBYWAmzV1gnXZbvrumjK/uehYVYFnN58dZVdZDyhLTmSTNj\n" +
	"BKINgZgFcQKBgHr27oQTo29s09ZEChf3XuQqP6LFgeyLvlw98kuk6AQuESWOG4sC\n" +
	"AngqVxOPM8Fnk95IZYcExAdJ+PmJV8FJq6rueT8PG+AujcR3jay55StgjBicLgvg\n" +
	"aBuloYpCVGjsEMcnXeeDiggM/eyBG512rVeHKZiTeZSkyFCNm+JN9lWzAoGAU0/4\n" +
	"Bb3iGk3NKe/3rRlR6YBf3+lerpSmRTRD53fz7A4Rp4ObTfYyYycKowwldtVDovES\n" +
	"2wGR9suC9VuBelVBMZhO1pbmtiUoux8KQMXJn8w16ENtIUJheNpFRi1hsf1ZlZuq\n" +
	"qmRbPSImBkc5icubPIvoXttkNdPebeRyoAOjaLECgYBtMKADx71RqTVyq8xRu7ZH\n" +
	"UDO/HccBFp0vojEkmTLTN9BbfUJLnamrQIe7X2VYT0f8BsZ5U2QS7J0ikkG4hysn\n" +
	"W2GJ+0L9oq7ZwciozRb+c+ZGPmH2iXf+GQYVffFlrKPQ7GIcWEMWCIboAzeAEf09\n" +
	"JvBCMZkRkwU4aRXI1i+lag==\n" +
	"-----END PRIVATE KEY-----\n"

func TestRegister(t *testing.T) {

	ref := activity.GetRef(&Activity{})
	act := activity.Get(ref)

	assert.NotNil(t, act)
}

func TestJWT_Create(t *testing.T) {

	ac := &Activity{}
	tc := test.NewActivityContext(ac.Metadata())

	acInput := &Input{
		PrivateKey: privateKey,
		Audience:   audience,
		Subject:    subject,
		Issuer:     issuer,
	}

	tc.SetInputObject(acInput)

	// when
	done, _ := ac.Eval(tc)

	// then
	acOutput := &Output{}
	tc.GetOutputObject(acOutput)

	//check JWT Validity by parsing the token and check claims
	parsedTokenClaims := parseJWTToken(acOutput.JWTToken).Claims.(jwt.MapClaims)
	issuerParsed := parsedTokenClaims["iss"]

	assert.True(t, done)
	expectedResult := issuer
	assert.Equal(t, expectedResult, issuerParsed)

}

func parseJWTToken(jwtToken string) *jwt.Token {

	tok, _ := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	return tok
}
