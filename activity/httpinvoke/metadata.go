package httpinvoke

import (
	"github.com/project-flogo/core/data/coerce"
)

type Settings struct {
	//UseEnvProp        string                 `md:"useEnvProp,default,allowed(YES,NO)"`                // Do we want to use an environment property for the uri
	//Uri               string                 `md:"uri,required"`                                      // The URI of the service to invoke
	SelectMethod  bool                   `md:"true,false"`    // The HTTP method to invoke
	Method        string                 `md:"method"`        // The HTTP method to invoke
	Proxy         string                 `md:"proxy"`         // The address of the proxy server to be use
	Timeout       int                    `md:"timeout"`       // The request timeout in seconds
	SkipSSLVerify bool                   `md:"skipSSLVerify"` // Skip SSL validation
	CertFile      string                 `md:"certFile"`      // Path to PEM encoded client certificate
	KeyFile       string                 `md:"keyFile"`       // Path to PEM encoded client key
	CAFile        string                 `md:"CAFile"`        // Path to PEM encoded root certificates file
	SSLConfig     map[string]interface{} `md:"sslConfig"`     // SSL Configuration
}

type Input struct {
	PathParams        map[string]string `md:"pathParams"`        // The query parameters (e.g., 'id' in http://.../pet?id=someValue )
	QueryParams       map[string]string `md:"queryParams"`       // The path parameters (e.g., 'id' in http://.../pet/:id/name )
	Headers           map[string]string `md:"headers"`           // The HTTP header parameters
	AdditionalHeaders map[string]string `md:"additionalHeaders"` // Additional HTTP headers parameters
	Content           interface{}       `md:"content"`           // The message content to send. This is only used in POST, PUT, and PATCH
	Method            string            `md:"method"`            // The HTTP method to use for this request
	ProxyPass         string            `md:"proxyPass"`         // The Base URL of the endpoint
}

func (i *Input) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"pathParams":        i.PathParams,
		"queryParams":       i.QueryParams,
		"headers":           i.Headers,
		"additionalHeaders": i.AdditionalHeaders,
		"content":           i.Content,
		"method":            i.Method,
		"proxyPass":         i.ProxyPass,
	}
}

func (i *Input) FromMap(values map[string]interface{}) error {

	var err error
	i.PathParams, err = coerce.ToParams(values["pathParams"])
	if err != nil {
		return err
	}
	i.QueryParams, err = coerce.ToParams(values["queryParams"])
	if err != nil {
		return err
	}
	i.Headers, err = coerce.ToParams(values["headers"])
	if err != nil {
		return err
	}
	i.AdditionalHeaders, err = coerce.ToParams(values["additionalHeaders"])
	if err != nil {
		return err
	}
	i.Content = values["content"]
	i.Method, err = coerce.ToString(values["method"])
	if err != nil {
		return err
	}
	i.ProxyPass, err = coerce.ToString(values["proxyPass"])
	return nil
}

type Output struct {
	Status  int               `md:"status"`  // The HTTP status code
	Data    interface{}       `md:"data"`    // The HTTP response data
	Headers map[string]string `md:"headers"` // The HTTP response headers
	Cookies []interface{}     `md:"cookies"` // The response cookies (from 'Set-Cookie')
}

func (o *Output) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"status":  o.Status,
		"data":    o.Data,
		"headers": o.Headers,
		"cookies": o.Cookies,
	}
}

func (o *Output) FromMap(values map[string]interface{}) error {

	var err error
	o.Status, err = coerce.ToInt(values["status"])
	if err != nil {
		return err
	}
	o.Data, _ = values["data"]

	o.Headers, err = coerce.ToParams(values["headers"])
	if err != nil {
		return err
	}

	o.Cookies, err = coerce.ToArray(values["cookies"])
	if err != nil {
		return err
	}

	return nil
}
