package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/project-flogo/core/data/coerce"
	"github.com/project-flogo/core/data/expression/function"
	"github.com/stretchr/testify/assert"
	"testing"
)

const issuer = "3MVG9OjW2TAjFKUvW_FK.xteDX5._vfl57Df0i6pFszXCaQNaZDHvCnUD5yJ8Lyk2aN5Q24KumNNv6M6AaFT9"
const audience = "https://test.salesforce.com"
const subject = "lp.ngi.tibco@leaseplan.com.lpdev"
const privateKey = "-----BEGIN PRIVATE KEY----- MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCtIjxVzkBMKPBS 1LtqqRQEFKzEr9lWMMvrwmLcqDMLYG0fKk7BHv1BgzmSfcR8dvXAbjqPIaIxS6Mh AgERaIz4h6rPw2TUIKeaEKk8tEWn8BGbFRNe0pGjuT16VYbek+wPw8/anq0Y/mZ1 mlTonU6t04tZX4RFVOEQlIUrmX7//eDmpoC7jV8ROhpPYKof5iJAaXk+EcmAq1DE DKymKLIt5B7zBwuY6mky6/c5f7Tp/HwVcpZ8ppmmkyd7cr9PzeEi3jz6455vgZrn UovVXlNv/fU2VxlZoAqiPIddzEjDIopIuRZ1SZ8J2aCwiQys5Is6k2WEeUBCSqhJ 0VywFcEHAgMBAAECggEABRtGZk2ADf8DH55QrNOx2HD3q5F4OpeT3C9OlS2M2+AL N+kai42rcJw7PXviKL2lf/iAV6ppS0Ts2dNiTq4jwkzWF+yuc6dG6j9ljnnOuCZX jphvitNxIkAbdRlCshvw0YI4Bj2540vVn9BegsHpCS19JbSwhQ782G1ZBDEx0sEQ kycmRH1EvxoXHbU/yoXVqcoFo4ug1frkC/wVJDfP0Y4XaiM00+8YR1tnKSGb92GR Cj92QXT6/U11ptFl7WbHFJp6XQemPJe199Nr9TGSdl6coGWXALPw39voosM4T+4L 7wTCOn64exDo3PuA2cT0eGNflNsr40PzZ9aV4VzNIQKBgQD/c5eaKNio20IKJIDt 4AjK8jHqLiWWqoyyE0kJ5tt714BVbWfSmgxu9AIXwzrxeiGP3uwW5w4lCUsuKwka FayqRHmKc2awIPZTxcCoVN1RuP2VQlgtPGpF2cnfdVJ7TSEkl1W1VrACImgokQew fikQHLQM/hP6014q8XxsuMwR9wKBgQCtgWXbGVKta8KHpusw9NKWyuGu5359lSEh 86Cn31uCtG6EwcxjW1FvIKCzBmPfg8hTZ9uWo5pAIcpuFiJLufhcKlaH8yhEwYGJ JVviGJp65u8GsI6QKhBYWAmzV1gnXZbvrumjK/uehYVYFnN58dZVdZDyhLTmSTNj BKINgZgFcQKBgHr27oQTo29s09ZEChf3XuQqP6LFgeyLvlw98kuk6AQuESWOG4sC AngqVxOPM8Fnk95IZYcExAdJ+PmJV8FJq6rueT8PG+AujcR3jay55StgjBicLgvg aBuloYpCVGjsEMcnXeeDiggM/eyBG512rVeHKZiTeZSkyFCNm+JN9lWzAoGAU0/4 Bb3iGk3NKe/3rRlR6YBf3+lerpSmRTRD53fz7A4Rp4ObTfYyYycKowwldtVDovES 2wGR9suC9VuBelVBMZhO1pbmtiUoux8KQMXJn8w16ENtIUJheNpFRi1hsf1ZlZuq qmRbPSImBkc5icubPIvoXttkNdPebeRyoAOjaLECgYBtMKADx71RqTVyq8xRu7ZH UDO/HccBFp0vojEkmTLTN9BbfUJLnamrQIe7X2VYT0f8BsZ5U2QS7J0ikkG4hysn W2GJ+0L9oq7ZwciozRb+c+ZGPmH2iXf+GQYVffFlrKPQ7GIcWEMWCIboAzeAEf09 JvBCMZkRkwU4aRXI1i+lag== -----END PRIVATE KEY-----"

const expiry = 180

func TestFnGenerateJWT_Eval(t *testing.T) {
	f := &fnGenerateJWT{}

	token, _ := function.Eval(f, privateKey, audience, issuer, subject, expiry)
	//check JWT Validity by parsing the token and check claims
	parsedTokenClaims := parseJWTToken(coerce.ToString(token)).Claims.(jwt.MapClaims)
	issuerParsed := parsedTokenClaims["iss"]

	expectedResult := issuer
	assert.Equal(t, expectedResult, issuerParsed)

}

func parseJWTToken(jwtToken string, err error) *jwt.Token {

	tok, _ := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	return tok
}
