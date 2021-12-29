package grafanacloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
)

type GrafanaAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e GrafanaAPIError) Error() string {
	return fmt.Sprintf("failed to perform operation on grafana api code: %s, err: %s", e.Code, e.Message)
}

type withHeader struct {
	http.Header
	rt http.RoundTripper
}

type Link struct {
	Rel string `json:"rel"`

	Href string `json:"href"`
}

type Token struct {
	Id        int    `json:"id"`
	OrgId     int    `json:"orgId"`
	OrgSlug   string `json:"orgSlug"`
	OrgName   string `json:"orgName"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Token     string `json:"token"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	FirstUsed string `json:"firstUsed"`
	Links     []Link `json:"links"`
}

type GetTokenResponse struct {
	Items []Token `json:"items"`
}

func WithHeader(rt http.RoundTripper) withHeader {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return withHeader{Header: make(http.Header), rt: rt}
}

func (h withHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.Header {
		req.Header[k] = v
	}

	return h.rt.RoundTrip(req)
}

type Client struct {
	BaseURL   string
	UserAgent string

	httpClient *http.Client
}

func createTokenName(role string) string {
	lowerRole := strings.ToLower(role)

	return fmt.Sprintf("vault-%s-%d", lowerRole, time.Now().UnixNano())
}

func (c *Client) findToken(name string) (*Token, error) {
	tokens, err := c.GetTokens()
	if err != nil {
		return nil, err
	}

	for _, curToken := range tokens.Items {
		if curToken.Name == name {
			return &curToken, nil
		}
	}

	return nil, nil
}

func (c *Client) performGrafanaAPIOperation(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errwrap.Wrapf("error attempting request: {{err}}", err)
	}

	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		var grafanaError GrafanaAPIError
		err = json.NewDecoder(resp.Body).Decode(&grafanaError)
		if err != nil {
			return nil, errwrap.Wrapf("error decoding error response from grafana cloud: {{err}}", err)
		}

		return nil, grafanaError
	}

	return resp, nil
}

func (c *Client) GetTokens() (*GetTokenResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL, nil)

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jsonResponse GetTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, errwrap.Wrapf("error decoding get token response: {{err}}", err)
	}

	return &jsonResponse, nil
}

func (c *Client) CreateToken(tokenName string, role string) (*Token, error) {
	postBody, err := json.Marshal(map[string]string{
		"name": tokenName,
		"role": role,
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed to marshal the request body: {{err}}", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL, bytes.NewBuffer(postBody))
	if err != nil {
		return nil, errwrap.Wrapf("error creating 'create token' request: {{err}}", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jsonResponse Token
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, errwrap.Wrapf("error decoding create token response: {{err}}", err)
	}

	return &jsonResponse, nil
}

func (c *Client) DeleteToken(name string) error {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/"+name, nil)

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func createClient(token string, orgSlug string) (*Client, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	rt := WithHeader(client.Transport)
	rt.Set("Authorization", "Bearer "+token)
	client.Transport = rt

	return &Client{
		BaseURL:    fmt.Sprintf("https://grafana.com/api/orgs/%s/api-keys", orgSlug),
		httpClient: client,
	}, nil

}

func (b *backend) client(ctx context.Context, s logical.Storage) (*Client, error) {
	conf, err := b.readConfigToken(ctx, s)
	if err != nil {
		return nil, err
	}
	return createClient(conf.Token, conf.OrganizationSlug)
}
