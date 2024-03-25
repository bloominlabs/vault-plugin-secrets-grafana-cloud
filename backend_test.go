package grafanacloud

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func (c *Client) testCreateToken(t *testing.T, body CreateTokenRequest) (*TokenResponse, func()) {
	t.Helper()

	token, err := c.CreateToken(body)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		c.DeleteToken(token.ID)
		if err != nil {
			t.Errorf("failed to delete token '%s'. please ensure it is deleted in grafana cloud. err: %s", token.Name, err.Error())
		}
	}

	return token, cleanup
}

func testCreateClient(t *testing.T, token string) (*Client, string) {
	t.Helper()

	client, err := createClient(token)
	if err != nil {
		t.Fatal(err)
	}

	decodedToken, err := DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	tokenResp, err := client.GetTokenByName(decodedToken.TokenName)
	if err != nil {
		t.Fatal(err)
	}

	return client, tokenResp.AccessPolicyID
}

func TestBackend_config_token(t *testing.T) {
	GRAFANA_TOKEN := os.Getenv("TEST_GRAFANA_TOKEN")

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	client, ACCESS_POLICY_ID := testCreateClient(t, GRAFANA_TOKEN)

	localTokenName := fmt.Sprintf("integration-test-%d", time.Now().UnixNano())
	viewerToken, tokenCleanup := client.testCreateToken(t, CreateTokenRequest{
		AccessPolicyID: ACCESS_POLICY_ID,
		Name:           localTokenName,
		DisplayName:    localTokenName,
		ExpiresAt:      time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokenCleanup()

	testCases := []struct {
		name                  string
		configData            accessTokenConfig
		expectedWriteResponse map[string]interface{}
		expectedReadResponse  map[string]interface{}
	}{
		{
			"errorsWithMissingPolicyID",
			accessTokenConfig{Token: "test"},
			map[string]interface{}{"error": "failed to create client: failed to decode tokens: invalid character 'µ' looking for beginning of value"},
			map[string]interface{}{"error": "configuration does not exist. did you configure 'config/token'?"},
		},
		{
			"errorsWithInvalidCredentials",
			accessTokenConfig{Token: "eyJrIjoiZTcxYjAyZTU0YjliNmExYjYxNDhmODM5MDFlNTE4YWU2N2NjNWQ5MyIsIm4iOiJ0ZXN0LXZhdWx0LWxvY2FsIiwiaWQiOjQ1NjgxOX0="},
			map[string]interface{}{"error": "failed to get token: error returned from grafana at url 'https://grafana.com/api/v1/tokens?name=test-vault-local&region=' code: InvalidCredentials, err: Token invalid"},
			map[string]interface{}{"error": "configuration does not exist. did you configure 'config/token'?"},
		},
		{
			"succeedsWithValidToken",
			accessTokenConfig{Token: viewerToken.Token},
			nil,
			map[string]interface{}{
				"accessPolicyID": viewerToken.AccessPolicyID,
				"id":             viewerToken.ID,
				"token":          viewerToken.Token,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configData := map[string]interface{}{
				"token": testCase.configData.Token,
			}

			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/token",
				Storage:   config.StorageView,
				Data:      configData,
			}

			resp, err := b.HandleRequest(context.Background(), confReq)
			if err != nil {
				t.Fatal(err)
			}

			if testCase.expectedWriteResponse == nil {
				assert.Nil(t, resp)
			} else {
				assert.NotNil(t, resp)
				assert.NotNil(t, testCase.expectedWriteResponse)
				assert.Equal(t, testCase.expectedWriteResponse, resp.Data)
			}

			confReq.Operation = logical.ReadOperation
			resp, _ = b.HandleRequest(context.Background(), confReq)
			assert.Equal(t, testCase.expectedReadResponse, resp.Data)
		})
	}
}

func TestBackend_rotate_root(t *testing.T) {
	GRAFANA_TOKEN := os.Getenv("TEST_GRAFANA_TOKEN")

	if GRAFANA_TOKEN == "" {
		t.Skip("missing 'TEST_GRAFANA_TOKEN' or 'TEST_GRAFANA_ORG_SLUG'. skipping...")
	}

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	client, ACCESS_POLICY_ID := testCreateClient(t, GRAFANA_TOKEN)

	testCases := []struct {
		name          string
		tokenRole     string
		expectedError map[string]interface{}
	}{
		{
			"happyPath",
			adminSlug,
			nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			localTokenName := fmt.Sprintf("integration-test-%d", time.Now().UnixNano())
			originalToken, tokenCleanup := client.testCreateToken(t, CreateTokenRequest{
				AccessPolicyID: ACCESS_POLICY_ID,
				Name:           localTokenName,
				DisplayName:    localTokenName,
				ExpiresAt:      time.Now().UTC().Add(5 * time.Minute),
			})

			defer tokenCleanup()

			configData := map[string]interface{}{
				"token": originalToken.Token,
			}

			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/token",
				Storage:   config.StorageView,
				Data:      configData,
			}

			resp, err := b.HandleRequest(context.Background(), confReq)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("failed to configure mount: resp:%#v err:%s", resp, err)
			}

			confReq = &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/rotate-root",
				Storage:   config.StorageView,
				Data:      map[string]interface{}{},
			}

			resp, err = b.HandleRequest(context.Background(), confReq)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("failed to rotate token: resp:%#v err:%s", resp, err)
			}
			newTokenID := resp.Data["id"].(string)
			defer func() {
				err := client.DeleteToken(newTokenID)
				if err != nil {
					t.Fatalf("failed to delete token '%s'. please ensure it is deleted in grafana cloud. err: %s", originalToken.Name, err.Error())
				}
			}()

			// Ensure the new token exists and has admin permissions
			foundToken, err := client.GetToken(newTokenID)
			assert.Nil(t, err)
			assert.Equal(t, foundToken.AccessPolicyID, ACCESS_POLICY_ID)

			// Ensure that the old token was deleted
			foundToken, err = client.GetToken(originalToken.ID)
			assert.Nil(t, foundToken)
			assert.Nil(t, err)
		})
	}
}

func TestBackend_token_create(t *testing.T) {
	GRAFANA_TOKEN := os.Getenv("TEST_GRAFANA_TOKEN")

	if GRAFANA_TOKEN == "" {
		t.Skip("missing 'TEST_GRAFANA_TOKEN' or 'TEST_GRAFANA_ORG_SLUG'. skipping...")
	}

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	decodedToken, err := DecodeToken(GRAFANA_TOKEN)
	if err != nil {
		t.Fatal(err)
	}

	client, err := createClient(GRAFANA_TOKEN)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name          string
		policy        map[string]interface{}
		expectedError map[string]interface{}
	}{
		{
			"stack-readers",
			map[string]interface{}{
				"displayName": "Stack Readers Integration Test",
				"scopes":      []string{"metrics:read"},
				"realms": []map[string]interface{}{
					{
						"type":       "org",
						"identifier": decodedToken.Organization,
					},
				},
			},
			nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configData := map[string]interface{}{
				"token": GRAFANA_TOKEN,
			}

			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/token",
				Storage:   config.StorageView,
				Data:      configData,
			}

			_, err := b.HandleRequest(context.Background(), confReq)
			if err != nil {
				t.Fatal(err)
			}

			localName := fmt.Sprintf("%s-integration-test-%d", testCase.name, time.Now().UnixNano())
			accessPolicyData := map[string]interface{}{
				"policy": testCase.policy,
			}
			accessPolicyRequest := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "access_policies/" + localName,
				Storage:   config.StorageView,
				Data:      accessPolicyData,
			}

			accessPolicyResponse, err := b.HandleRequest(context.Background(), accessPolicyRequest)
			if err != nil {
				t.Fatal(err)
			}

			credsReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("creds/%s", localName),
				Storage:   config.StorageView,
			}

			resp, err := b.HandleRequest(context.Background(), credsReq)
			if err != nil {
				t.Fatal(err)
			}

			createdTokenID, ok := resp.Data["id"].(string)
			newToken, err := client.GetToken(createdTokenID)
			// Ensures that in the case were we expect an error, but the token is
			// created successfully that the token is always deleted
			if ok {
				if err != nil || newToken == nil {
					t.Fatalf("failed to find token returned by endpoint: newToken:%#v err:%s", newToken, err)
				}
				defer func() {
					err := client.DeleteToken(newToken.Name)
					if err != nil {
						t.Fatalf("failed to delete token '%s'. please ensure it is deleted in grafana cloud. err: %s", newToken.Name, err.Error())
					}
				}()

				// If this case fails when you expected an error, that means the token
				// is getting created succesfully
				assert.Equal(t, newToken.AccessPolicyID, accessPolicyResponse.Data["id"].(string))
			}

			if testCase.expectedError != nil {
				assert.Equal(t, testCase.expectedError, resp.Data)
			}
		})
	}
}
