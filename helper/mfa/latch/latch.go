// Package latch provides a Latch MFA handler to authenticate users
// with Latch. This handler is registered as the "latch" type in
// mfa_config.
package latch

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// LatchPaths returns path functions to configure Latch.
func LatchPaths() []*framework.Path {
	return []*framework.Path{
		pathLatchAccess(),
		pathLatchUsers(),
	}
}

// LatchRootPaths returns the paths that are used to configure Latch.
func LatchRootPaths() []string {
	return []string{
		"latch/access",
		"latch/users",
	}
}

// LatchHandler interacts with the Latch API to authenticate a user
// login request. If successful, the original response from the login
// backend is returned.
func LatchHandler(req *logical.Request, d *framework.FieldData, resp *logical.Response) (
	*logical.Response, error) {

	latchAuthClient, err := GetLatchAuthClient(req)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	username, ok := resp.Auth.Metadata["username"]
	if !ok {
		return logical.ErrorResponse("Could not read username for Latch/MFA"), nil
	}

	latchUser, err := LatchUser(req.Storage, username)
	if err != nil {
		return nil, err
	}
	if latchUser == nil {
		return nil, nil
	}

	statusIsOn, err := latchAuthClient.StatusIsOn(latchUser.Account)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if !statusIsOn {
		return logical.ErrorResponse("Latch switch is off"), nil
	}

	return resp, nil
}
