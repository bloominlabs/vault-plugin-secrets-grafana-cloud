package grafanacloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type Metadata struct {
	Region string `json:"r"`
}

type GrafanaToken struct {
	Organization string   `json:"o"`
	TokenName    string   `json:"n"`
	K            string   `json:"k"`
	Metadata     Metadata `json:"m"`
}

type CreateTokenRequest struct {
	AccessPolicyID string    `json:"accessPolicyId"`
	Name           string    `json:"name"`
	DisplayName    string    `json:"displayName"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type TokenResponse struct {
	ID             string    `json:"id"`
	AccessPolicyID string    `json:"accessPolicyId"`
	Name           string    `json:"name"`
	DisplayName    string    `json:"displayName"`
	ExpiresAt      time.Time `json:"expiresAt"`
	FirstUsedAt    time.Time `json:"firstUsedAt"`
	LastUsedAt     time.Time `json:"lastUsedAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Token          string    `json:"token"`
}

func DecodeToken(token string) (GrafanaToken, error) {
	token = strings.TrimPrefix(token, "glc_")
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return GrafanaToken{}, err
	}

	var grafanaToken GrafanaToken
	if err := json.Unmarshal(decodedToken, &grafanaToken); err != nil {
		return GrafanaToken{}, err
	}

	return grafanaToken, nil
}

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

type GetTokenResponse struct {
	Items []TokenResponse `json:"items"`
}

type AccessPolicy struct {
	ID          string   `json:"id,omitempty"`
	OrgID       string   `json:"orgId,omitempty"`
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Scopes      []string `json:"scopes"`
	Realms      []struct {
		Type          string `json:"type,omitempty"`
		Identifier    string `json:"identifier,omitempty"`
		LabelPolicies []struct {
			Selector string `json:"selector,omitempty"`
		} `json:"labelPolicies,omitempty"`
	} `json:"realms,omitempty"`
	Conditions struct {
		AllowedSubnets []string `json:"allowedSubnets,omitempty"`
	} `json:"conditions,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
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
	region     string
}

func createTokenName(role string) string {
	lowerRole := strings.ToLower(role)

	return fmt.Sprintf("vault-%s-%d", lowerRole, time.Now().UnixNano())
}

func (c *Client) performGrafanaAPIOperation(req *http.Request) (*http.Response, error) {
	newParams := req.URL.Query()
	newParams.Add("region", c.region)
	req.URL.RawQuery = newParams.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error attempting request: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		defer resp.Body.Close()
		var grafanaError GrafanaAPIError
		err = json.NewDecoder(resp.Body).Decode(&grafanaError)
		if err != nil {
			return nil, fmt.Errorf("error decoding error response from grafana cloud: %w", err)
		}

		return nil, fmt.Errorf("error returned from grafana at url '%s' code: %s, err: %s", req.URL.String(), grafanaError.Code, grafanaError.Message)
	}

	return resp, nil
}

func (c *Client) GetTokenByName(name string) (*TokenResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/tokens", nil)
	if err != nil {
		return nil, err
	}
	queryParams := req.URL.Query()
	queryParams.Add("name", name)
	req.URL.RawQuery = queryParams.Encode()

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jsonResponse GetTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding get token response: %w", err)
	}

	if len(jsonResponse.Items) != 1 {
		return nil, fmt.Errorf("found an unexpected number of tokens with name '%s': %v", name, jsonResponse.Items)
	}

	return &jsonResponse.Items[0], nil

}

func (c *Client) GetToken(id string) (*TokenResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/tokens/"+id, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jsonResponse TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding get token response: %w", err)
	}

	return &jsonResponse, nil
}

func (c *Client) CreateToken(reqBody CreateTokenRequest) (*TokenResponse, error) {
	postBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the request body: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/tokens", bytes.NewBuffer(postBody))
	if err != nil {
		return nil, fmt.Errorf("error creating 'create token' request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jsonResponse TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding create token response: %w", err)
	}

	return &jsonResponse, nil
}

func (c *Client) UpdateToken(id string, expirationDate time.Time) error {
	data, err := json.Marshal(map[string]interface{}{
		"expiresAt": expirationDate,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	req, err := http.NewRequest("POST", c.BaseURL+"/tokens/"+id, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (c *Client) DeleteToken(id string) error {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/tokens/"+id, nil)
	if err != nil {
		return err
	}

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (c *Client) CreateAccessPolicy(policy map[string]interface{}) (*AccessPolicy, error) {
	postBody, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the request body: %w", err)
	}
	req, err := http.NewRequest("POST", c.BaseURL+"/accesspolicies", bytes.NewBuffer(postBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jsonResponse AccessPolicy
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding create access policy response: %w", err)
	}

	return &jsonResponse, nil
}

func (c *Client) DeleteAccessPolicy(id string) (bool, error) {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/accesspolicies/"+id, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.performGrafanaAPIOperation(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return true, nil
}

func createClient(token string) (*Client, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	rt := WithHeader(client.Transport)
	rt.Set("Authorization", "Bearer "+token)
	client.Transport = rt

	decodedToken, err := DecodeToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tokens: %w", err)
	}

	return &Client{
		BaseURL:    "https://grafana.com/api/v1",
		httpClient: client,
		region:     decodedToken.Metadata.Region,
	}, nil

}

func (b *backend) client(ctx context.Context, s logical.Storage) (*Client, error) {
	conf, err := b.readConfigToken(ctx, s)
	if err != nil {
		return nil, err
	}
	return createClient(conf.Token)
}
