package latch

import (
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLatchUsers() *framework.Path {
	return &framework.Path{
		Pattern: "latch/users/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Username for this user.",
			},

			"account": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Latch account.",
			},

			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Latch token",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: pathUserDelete,
			logical.ReadOperation:   pathUserRead,
			logical.WriteOperation:  pathUserWrite,
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func LatchUser(s logical.Storage, n string) (*LatchUserEntry, error) {
	entry, err := s.Get("latchuser/" + strings.ToLower(n))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result LatchUserEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func pathUserDelete(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	latchUser, err := LatchUser(req.Storage, strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	if latchUser == nil {
		return nil, nil
	}

	client, err := GetLatchAuthClient(req)
	if err != nil {
		return nil, err
	}

	err = client.Unpair(latchUser.Account)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Delete("latchuser/" + strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func pathUserRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	latchUser, err := LatchUser(req.Storage, strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	if latchUser == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account": latchUser.Account,
		},
	}, nil
}

func pathUserWrite(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	token := d.Get("token").(string)

	client, err := GetLatchAuthClient(req)
	if err != nil {
		return nil, err
	}

	accountId, err := client.Pair(token)
	if err != nil {
		return nil, err
	}

	// Store it
	entry, err := logical.StorageEntryJSON("latchuser/"+name, &LatchUserEntry{
		Account: accountId,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type LatchUserEntry struct {
	// Account is the Latch account
	// PasswordHash, but is retained for backwards compatibilty.
	Account string
}

const pathUserHelpSyn = `
Manage users allowed to authenticate with latch
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete users
that are allowed to authenticate.

to enroll an user to a Latch App:

  vault write auth/[mountpoint]/latch/users/[username] token 

to unenroll an user to a latch App

  vault delete auth/[mountpoint]/latch/users/[username]

you can see the account id associated with the user

  vault read auth/[mountpoint]/latch/users/[username]
`
