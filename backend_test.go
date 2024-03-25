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

func (c *Client) testCreateToken(t *testing.T, body CreateTokenRequest) (*TokenResponse, func(), error) {
	token, err := c.CreateToken(body)
	cleanup := func() {
		c.DeleteToken(token.ID)
		if err != nil {
			t.Fatalf("failed to delete token '%s'. please ensure it is deleted in grafana cloud. err: %s", token.Name, err.Error())
		}
	}

	return token, cleanup, err
}

func TestBackend_config_token(t *testing.T) {
	GRAFANA_TOKEN := os.Getenv("TEST_GRAFANA_TOKEN")

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	client, err := createClient(GRAFANA_TOKEN)
	if err != nil {
		t.Fatal(err)
	}

	decodedToken, err := DecodeToken(GRAFANA_TOKEN)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := client.GetTokenByName(decodedToken.TokenName)
	if err != nil {
		t.Fatal(err)
	}
	ACCESS_POLICY_ID := tokens.AccessPolicyID

	localTokenName := fmt.Sprintf("integration-test-%d", time.Now().UnixNano())
	viewerToken, tokenCleanup, err := client.testCreateToken(t, CreateTokenRequest{
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

// func TestBackend_rotate_root(t *testing.T) {
// 	GRAFANA_TOKEN := os.Getenv("TEST_GRAFANA_TOKEN")
// 	GRAFANA_ORG_SLUG := os.Getenv("TEST_GRAFANA_ORG_SLUG")
//
// 	if GRAFANA_ORG_SLUG == "" || GRAFANA_TOKEN == "" {
// 		t.Skip("missing 'TEST_GRAFANA_TOKEN' or 'TEST_GRAFANA_ORG_SLUG'. skipping...")
// 	}
//
// 	config := logical.TestBackendConfig()
// 	config.StorageView = &logical.InmemStorage{}
// 	b, err := Factory(context.Background(), config)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	client, err := createClient(GRAFANA_TOKEN)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	testCases := []struct {
// 		name          string
// 		tokenRole     string
// 		expectedError map[string]interface{}
// 	}{
// 		{
// 			"happyPath",
// 			adminSlug,
// 			nil,
// 		},
// 	}
//
// 	for _, testCase := range testCases {
// 		t.Run(testCase.name, func(t *testing.T) {
// 			token, tokenCleanup, err := client.testCreateToken(t, fmt.Sprintf("integration-test-%s-%d", testCase.name, time.Now().UnixNano()), testCase.tokenRole)
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			defer tokenCleanup()
//
// 			configData := map[string]interface{}{
// 				"token":   token.Token,
// 				"orgSlug": token.OrgSlug,
// 			}
//
// 			confReq := &logical.Request{
// 				Operation: logical.UpdateOperation,
// 				Path:      "config/token",
// 				Storage:   config.StorageView,
// 				Data:      configData,
// 			}
//
// 			resp, err := b.HandleRequest(context.Background(), confReq)
// 			if err != nil || (resp != nil && resp.IsError()) {
// 				t.Fatalf("failed to configure mount: resp:%#v err:%s", resp, err)
// 			}
//
// 			confReq = &logical.Request{
// 				Operation: logical.UpdateOperation,
// 				Path:      "config/rotate-root",
// 				Storage:   config.StorageView,
// 				Data:      map[string]interface{}{},
// 			}
//
// 			resp, err = b.HandleRequest(context.Background(), confReq)
// 			if err != nil || (resp != nil && resp.IsError()) {
// 				t.Fatalf("failed to rotate token: resp:%#v err:%s", resp, err)
// 			}
// 			newTokenName := resp.Data["name"].(string)
// 			defer func() {
// 				err := client.DeleteToken(newTokenName)
// 				if err != nil {
// 					t.Fatalf("failed to delete token '%s'. please ensure it is deleted in grafana cloud. err: %s", token.Name, err.Error())
// 				}
// 			}()
//
// 			// Ensure the new token exists and has admin permissions
// 			foundToken, err := client.findToken(newTokenName)
// 			assert.Equal(t, foundToken.OrgSlug, GRAFANA_ORG_SLUG)
// 			assert.Equal(t, foundToken.Role, adminSlug)
//
// 			// Ensure that the old token was deleted
// 			foundToken, err = client.findToken(token.Name)
// 			assert.Nil(t, foundToken)
// 			assert.Nil(t, err)
// 		})
// 	}
// }
//
// func TestBackend_token_create(t *testing.T) {
// 	GRAFANA_TOKEN := os.Getenv("TEST_GRAFANA_TOKEN")
// 	GRAFANA_ORG_SLUG := os.Getenv("TEST_GRAFANA_ORG_SLUG")
//
// 	if GRAFANA_TOKEN == "" || GRAFANA_ORG_SLUG == "" {
// 		t.Skip("missing 'TEST_GRAFANA_TOKEN' or 'TEST_GRAFANA_ORG_SLUG'. skipping...")
// 	}
//
// 	config := logical.TestBackendConfig()
// 	config.StorageView = &logical.InmemStorage{}
// 	b, err := Factory(context.Background(), config)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	client, err := createClient(GRAFANA_TOKEN)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	testCases := []struct {
// 		roleName      string
// 		expectedError map[string]interface{}
// 	}{
// 		{
// 			adminSlug,
// 			nil,
// 		},
// 		{
// 			"Viewer",
// 			nil,
// 		},
// 		{
// 			"MetricsPublisher",
// 			nil,
// 		},
// 		{
// 			"viewer",
// 			map[string]interface{}{"error": "err while creating token with role 'viewer' from grafana cloud. code: InvalidArgument, err: Value must be one of [Viewer, MetricsPublisher, PluginPublisher, Editor, Admin]: role"},
// 		},
// 	}
//
// 	for _, testCase := range testCases {
// 		t.Run(testCase.roleName, func(t *testing.T) {
// 			configData := map[string]interface{}{
// 				"token":   GRAFANA_TOKEN,
// 				"orgSlug": GRAFANA_ORG_SLUG,
// 			}
//
// 			confReq := &logical.Request{
// 				Operation: logical.UpdateOperation,
// 				Path:      "config/token",
// 				Storage:   config.StorageView,
// 				Data:      configData,
// 			}
//
// 			_, err := b.HandleRequest(context.Background(), confReq)
// 			if err != nil {
// 				t.Fatal(err)
// 			}
//
// 			confReq = &logical.Request{
// 				Operation: logical.ReadOperation,
// 				Path:      fmt.Sprintf("creds/%s", testCase.roleName),
// 				Storage:   config.StorageView,
// 			}
//
// 			resp, err := b.HandleRequest(context.Background(), confReq)
// 			if err != nil {
// 				t.Fatal(err)
// 			}
//
// 			createdTokenName, ok := resp.Data["name"].(string)
// 			newToken, err := client.findToken(createdTokenName)
// 			// Ensures that in the case were we expect an error, but the token is
// 			// created successfully that the token is always deleted
// 			if ok {
// 				if err != nil || newToken == nil {
// 					t.Fatalf("failed to find token returned by endpoint: newToken:%#v err:%s", newToken, err)
// 				}
// 				defer func() {
// 					err := client.DeleteToken(newToken.Name)
// 					if err != nil {
// 						t.Fatalf("failed to delete token '%s'. please ensure it is deleted in grafana cloud. err: %s", newToken.Name, err.Error())
// 					}
// 				}()
//
// 				// If this case fails when you expected an error, that means the token
// 				// is getting created succesfully
// 				assert.Equal(t, newToken.Role, testCase.roleName)
// 				assert.Regexp(t, regexp.MustCompile(fmt.Sprintf("vault-%s-.*", strings.ToLower(testCase.roleName))), createdTokenName)
// 			}
//
// 			if testCase.expectedError != nil {
// 				assert.Equal(t, testCase.expectedError, resp.Data)
// 			}
// 		})
// 	}
// }
