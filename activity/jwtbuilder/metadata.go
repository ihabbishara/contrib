package jwtbuilder

import (
	"github.com/project-flogo/core/data/coerce"
)

type Input struct {
	PrivateKey string `md:"privateKey"`
	Audience   string `md:"audience"`
	Subject    string `md:"subject"`
	Issuer     string `md:"issuer"`
	//	Expiry     int    `md:"expiry"`
}

func (i *Input) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"privateKey": i.PrivateKey,
		"audience":   i.Audience,
		"subject":    i.Subject,
		"issuer":     i.Issuer,
		//		"expiry":     i.Expiry,
	}
}

func (i *Input) FromMap(values map[string]interface{}) error {
	var err error
	i.PrivateKey, err = coerce.ToString(values["privateKey"])
	i.Audience, err = coerce.ToString(values["audience"])
	i.Subject, err = coerce.ToString(values["subject"])
	i.Issuer, err = coerce.ToString(values["issuer"])
	//	i.Expiry, err = coerce.ToInt(values["expiry"])

	if err != nil {
		return err
	}
	return nil
}

type Output struct {
	JWTToken string `md:"jwttoken"`
}

func (o *Output) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"jwttoken": o.JWTToken,
	}
}

func (o *Output) FromMap(values map[string]interface{}) error {
	var err error
	o.JWTToken, err = coerce.ToString(values["jwttoken"])
	if err != nil {
		return err
	}

	return nil
}
