package grafanacloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListAccessPolicies(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "access_policies/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathAccessPolicyList,
		},

		HelpSynopsis:    pathListAccessPoliciesHelpSyn,
		HelpDescription: pathListAccessPoliciesHelpDesc,
	}
}

func pathAccessPolicies(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "access_policies/" + framework.GenericNameWithAtRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the access policy",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Access Policy Name",
				},
			},

			"policy": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The policy to apply for the access policy. Accepts all arguments specified by https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api/#create-an-access-policy`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathAccessPoliciesDelete,
			logical.ReadOperation:   b.pathAccessPoliciesRead,
			logical.UpdateOperation: b.pathAccessPoliciesWrite,
		},

		HelpSynopsis:    pathAccessPoliciesHelpSyn,
		HelpDescription: pathAccessPoliciesHelpDesc,
	}
}

func (b *backend) pathAccessPolicyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "access_policies/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathAccessPoliciesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing access policy name"), nil
	}

	entry, err := b.accessPoliciesRead(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	_, err = c.DeleteAccessPolicy(entry.Policy.ID)
	if err != nil {
		return logical.ErrorResponse("failed to delete access policy with id '%s': %s", entry.Policy.ID, err), nil

	}

	var respPolicy map[string]interface{}
	inrec, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resp: %w", err)
	}
	err = json.Unmarshal(inrec, &respPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp: %w", err)
	}

	err = req.Storage.Delete(ctx, "access_policies/"+name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathAccessPoliciesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing access policy name"), nil
	}
	entry, err := b.accessPoliciesRead(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var respPolicy map[string]interface{}
	inrec, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resp: %w", err)
	}
	err = json.Unmarshal(inrec, &respPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp: %w", err)
	}

	return &logical.Response{
		Data: respPolicy,
	}, nil
}

func (b *backend) pathAccessPoliciesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp logical.Response

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing access policy name"), nil
	}

	entry, err := b.accessPoliciesRead(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		entry = &accessPolicyEntry{}
	}

	var policy map[string]interface{}
	if policyRaw, ok := d.GetOk("policy"); ok {
		s, ok := d.Get("policy").(string)
		if !ok {
			return logical.ErrorResponse(fmt.Sprintf("cannot parse policy. raw: %q, err: %s", policyRaw.(string), err)), nil
		}

		err := json.Unmarshal([]byte(s), &policy)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("cannot unmarshall policy. raw: %q, err: %s", policyRaw.(string), err)), nil
		}
	}

	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	policy["name"] = name
	accessPolicy, err := c.CreateAccessPolicy(policy)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create policy '%s' in grafana cloud: %s", name, err)), nil
	}

	entry.Policy = *accessPolicy

	storageEntry, err := logical.StorageEntryJSON("access_policies/"+name, *entry)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("nil result when writing to storage")
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, err
	}

	var respData map[string]interface{}
	in, err := json.Marshal(accessPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	err = json.NewDecoder(bytes.NewBuffer(in)).Decode(&respData)
	resp.Data = respData

	return &resp, nil
}

func (b *backend) accessPoliciesRead(ctx context.Context, s logical.Storage, name string) (*accessPolicyEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}
	entryRaw, err := s.Get(ctx, "access_policies/"+name)
	if err != nil {
		return nil, err
	}
	var entry accessPolicyEntry
	if entryRaw != nil {
		if err := entryRaw.DecodeJSON(&entry); err != nil {
			return nil, err
		}
		return &entry, nil
	}

	return nil, nil
}

type accessPolicyEntry struct {
	Policy AccessPolicy
}

func compactJSON(input string) (string, error) {
	var compacted bytes.Buffer
	err := json.Compact(&compacted, []byte(input))
	return compacted.String(), err
}

const pathListAccessPoliciesHelpSyn = `List the existing access policies in this backend`

const pathListAccessPoliciesHelpDesc = `Access policies will be listed by the name.`

const pathAccessPoliciesHelpSyn = `
Read, write and reference access policy token can be made for.
`

const pathAccessPoliciesHelpDesc = `
This path allows you to read and write policy that are used to
create access policy tokens.`
