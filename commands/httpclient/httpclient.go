package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"os"

	"time"
	"unicode/utf8"

	"github.com/banai-ci/banai/infra"
	"github.com/dop251/goja"
)

//RequestOpt options to run an http request
type RequestOpt struct {
	IgnoreHTTPSChecks bool              `json:"ignoreHttpsChecks,omitempty"`
	AllowRedirect     bool              `json:"allowRedirect,omitempty"`
	Timeout           int               `json:"timeout,omitempty"`
	Header            map[string]string `json:"header,omitempty"`
	Cookies           []*http.Cookie    `json:"cookies,omitempty"`
	ContentType       string            `json:"contentType,omitempty"`
	Accept            string            `json:"accept,omitempty"`
}

var defaultHTTPClientRequestOpt = RequestOpt{
	IgnoreHTTPSChecks: true,
	AllowRedirect:     true,
	Timeout:           0,
	Header:            make(map[string]string),
	Cookies:           make([]*http.Cookie, 0),
	ContentType:       "json",
	Accept:            "json",
}

type responseInfo struct {
	RawBody []byte            `json:"rawBody,omitempty"`
	Status  int               `json:"status,omitempty"`
	Body    goja.Value        `json:"body,omitempty"`
	Header  map[string]string `json:"herader,omitempty"`
	Cookies []*http.Cookie    `json:"cookies,omitempty"`
}

var banai *infra.Banai

func createRequestByOpt(opt RequestOpt, urlPath string, method string, body io.Reader) (req *http.Request, err error) {

	if opt.Timeout > 0 {
		ctx, cancle := context.WithTimeout(context.Background(), time.Duration(opt.Timeout)*time.Second)
		defer cancle()
		req, err = http.NewRequestWithContext(ctx, method, urlPath, body)
		if err != nil {
			return
		}
	} else {
		req, err = http.NewRequest(method, urlPath, body)
		if err != nil {
			return
		}
	}

	for k, val := range opt.Header {
		req.Header[k] = []string{val}
	}

	for _, cookie := range opt.Cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}

	}

	switch opt.ContentType {
	case "json":
		req.Header["Content-Type"] = []string{"application/json"}

	}

	switch opt.ContentType {
	case "json":
		req.Header["Accept"] = []string{"application/json"}
	case "bin":
		req.Header["Accept"] = []string{"application/octet-stream"}
	case "text":
		req.Header["Accept"] = []string{"text/plain"}

	}

	return
}

func createHTTPClientFromOpt(reqOpt RequestOpt) (client *http.Client) {

	client = &http.Client{}

	if !reqOpt.AllowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	trans := &http.Transport{}

	if reqOpt.IgnoreHTTPSChecks {
		trans.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client.Transport = trans
	return
}

func createRequestByForm(opt RequestOpt, urlPath string, fields map[string]string, files map[string]string) (req *http.Request, err error) {
	var fieldWriter io.Writer
	var fileWriter io.Writer
	body := &bytes.Buffer{}
	var isFormWithFiles = false

	if files != nil && len(files) > 0 {
		isFormWithFiles = true
	}
	var multipartWriter *multipart.Writer

	if isFormWithFiles {
		multipartWriter = multipart.NewWriter(body)
		for k, v := range fields {
			fieldWriter, err = multipartWriter.CreateFormField(k)
			if err != nil {
				return
			}

			fieldWriter.Write([]byte(v))
		}

		var file *os.File
		for fieldName, fileName := range files {
			fileWriter, err = multipartWriter.CreateFormFile(fieldName, fileName)
			if err != nil {
				return
			}
			file, err = os.Open(fileName)
			if err != nil {
				return
			}
			_, err = io.Copy(fileWriter, file)
			file.Close()
		}
		multipartWriter.Close()

		req, err = http.NewRequest(http.MethodPost, urlPath, bytes.NewReader(body.Bytes()))
		if err != nil {
			return
		}

	} else {

		form := url.Values{}
		for k, v := range fields {

			form.Add(k, v)
		}
		req, err = http.NewRequest(http.MethodPost, urlPath, strings.NewReader(form.Encode()))
		if err != nil {
			return
		}

	}

	for k, val := range opt.Header {
		req.Header[k] = []string{val}
	}

	for _, cookie := range opt.Cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}

	}

	if isFormWithFiles {
		req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	} else {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	return
}

func responseInfoFromHTTPresponse(httpRes *http.Response) (res *responseInfo) {
	res = &responseInfo{}
	var err error
	if httpRes.Body != nil {
		defer httpRes.Body.Close()
		res.RawBody, err = ioutil.ReadAll(httpRes.Body)
		if err != nil {
			banai.Logger.Error(err)
			res.RawBody = nil
		}
	}
	res.Status = httpRes.StatusCode
	res.Body = banai.Jse.ToValue(res.RawBody)
	if utf8.Valid(res.RawBody) {
		res.Body = banai.Jse.ToValue(string(res.RawBody))
		var resObject map[string]interface{}
		err = json.Unmarshal(res.RawBody, &resObject)
		if err == nil {
			res.Body = banai.Jse.ToValue(resObject)
		} else {
			var resArr []map[string]interface{}
			err = json.Unmarshal(res.RawBody, &resArr)
			if err == nil {
				res.Body = banai.Jse.ToValue(resArr)
			}
		}

	}
	res.Header = make(map[string]string)
	for k, v := range httpRes.Header {
		res.Header[k] = strings.Join(v, ",")
	}

	res.Cookies = make([]*http.Cookie, 0)
	res.Cookies = append(res.Cookies, httpRes.Cookies()...)

	return
}

//******************** REST REQUESTS
func getRequest(urlPath string, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}
	req, err = createRequestByOpt(opt, urlPath, http.MethodGet, nil)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)

}

func postRequest(urlPath string, body []byte, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	bodyReader := bytes.NewBuffer(body)

	req, err = createRequestByOpt(opt, urlPath, http.MethodPost, bodyReader)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)

}
func putRequest(urlPath string, body []byte, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	bodyReader := bytes.NewBuffer(body)

	req, err = createRequestByOpt(opt, urlPath, http.MethodPut, bodyReader)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)

}

func patchRequest(urlPath string, body []byte, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	bodyReader := bytes.NewBuffer(body)

	req, err = createRequestByOpt(opt, urlPath, http.MethodPatch, bodyReader)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)

}

func deleteRequest(urlPath string, body []byte, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	bodyReader := bytes.NewBuffer(body)

	req, err = createRequestByOpt(opt, urlPath, http.MethodDelete, bodyReader)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)
}

func optionsRequest(urlPath string, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	req, err = createRequestByOpt(opt, urlPath, http.MethodOptions, nil)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)
}

func headRequest(urlPath string, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	req, err = createRequestByOpt(opt, urlPath, http.MethodHead, nil)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)
}

func httpPostForm(urlPath string, fields map[string]string, files map[string]string, reqOpt ...RequestOpt) *responseInfo {
	var req *http.Request
	var client *http.Client
	var err error
	var res *http.Response
	var opt = defaultHTTPClientRequestOpt

	if reqOpt != nil && len(reqOpt) > 0 {
		opt = reqOpt[0]
	}

	req, err = createRequestByForm(opt, urlPath, fields, files)
	banai.PanicOnError(err)
	client = createHTTPClientFromOpt(opt)

	res, err = client.Do(req)
	banai.PanicOnError(err)
	return responseInfoFromHTTPresponse(res)
}

//RegisterJSObjects register func to JS
func RegisterJSObjects(b *infra.Banai) {
	banai = b
	banai.Jse.GlobalObject().Set("httpGet", getRequest)
	banai.Jse.GlobalObject().Set("httpPost", postRequest)
	banai.Jse.GlobalObject().Set("httpPut", putRequest)
	banai.Jse.GlobalObject().Set("httpPatch", patchRequest)
	banai.Jse.GlobalObject().Set("httpDelete", deleteRequest)
	banai.Jse.GlobalObject().Set("httpOptions", optionsRequest)
	banai.Jse.GlobalObject().Set("httpHead", headRequest)
	banai.Jse.GlobalObject().Set("httpPostForm", httpPostForm)
}
