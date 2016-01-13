package latch

import (
	"fmt"

	"github.com/amassanet/golatch1"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLatchAccess() *framework.Path {
	return &framework.Path{
		Pattern: `latch/access`,
		Fields: map[string]*framework.FieldSchema{
			"app_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Latch App id",
			},
			"app_secret": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Latch App secret",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.WriteOperation: pathLatchAccessWrite,
		},

		HelpSynopsis:    pathLatchAccessHelpSyn,
		HelpDescription: pathLatchAccessHelpDesc,
	}
}

func GetLatchAuthClient(req *logical.Request) (*golatch1.LatchApp, error) {
	entry, err := req.Storage.Get("latch/access")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf(
			"Latch access credentials haven't been configured. Please configure\n" +
				"them at the 'latch/access' endpoint")
	}
	var access LatchAccess
	if err := entry.DecodeJSON(&access); err != nil {
		return nil, err
	}

	latchClient := golatch1.NewLatchApp(
		access.AppId,
		access.AppSecret,
	)
	return latchClient, nil
}

func pathLatchAccessWrite(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := logical.StorageEntryJSON("latch/access", LatchAccess{
		AppId:     d.Get("app_id").(string),
		AppSecret: d.Get("app_secret").(string),
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type LatchAccess struct {
	AppId     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
}

const pathLatchAccessHelpSyn = `
Configure the access keys and host for Latch API connections.
`

const pathLatchAccessHelpDesc = `
To authenticate users with Latch, the backend needs to know what host to connect to
and must authenticate with an application id key and secret key. This endpoint is used
to configure that information.
`
