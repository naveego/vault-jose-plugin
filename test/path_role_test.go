package josejwt_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/fatih/structs"

	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/vault/logical"
	jwt "github.com/naveego/vault-jose-plugin/plugin"
)

func TestCRUDRole(t *testing.T) {
	b, storage := getTestBackend(t)

	/***  TEST CREATE OPERATION ***/
	req := &logical.Request{
		Storage: storage,
	}

	resp, err := createRole(req, b, t, "test_role")
	resp, err = createRole(req, b, t, "test_role_two")
	resp, err = createRole(req, b, t, "test_role_three")

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	/***  TEST GET OPERATION ***/
	resp, err = getRole(req, b, t, "test_role")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	var returnedRole jwt.RoleStorageEntry
	err = mapstructure.Decode(resp.Data, &returnedRole)

	if returnedRole.Name != "test_role" {
		t.Fatalf("incorrect role name %s returned, not the same as saved value \n", returnedRole.Name)
	} else if returnedRole.Type != "jwt" {
		t.Fatalf("incorrect token type returned, not the same as saved value \n")
	}

	/***  TEST Delete OPERATION ***/
	resp, err = deleteRole(req, b, t, "test_role")
	resp, err = deleteRole(req, b, t, "test_role_two")
	resp, err = deleteRole(req, b, t, "test_role_three")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func createRole(req *logical.Request, b logical.Backend, t *testing.T, roleName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"type": "jwt",
	}

	req.Operation = logical.CreateOperation
	req.Path = fmt.Sprintf("role/%s", roleName)
	req.Data = data

	startTime := time.Now()
	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("'Test create role' took %s\n", time.Since(startTime))
	return resp, err
}

func createRoleFromEntry(b logical.Backend, storage logical.Storage, t *testing.T, entry jwt.RoleStorageEntry) (*logical.Response, error) {
	data := structs.Map(entry)
	delete(data, "role_id")

	req := &logical.Request{
		Storage: storage,
	}

	req.Operation = logical.CreateOperation
	req.Path = fmt.Sprintf("role/%s", entry.Name)
	req.Data = data

	startTime := time.Now()
	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("'Test create role' took %s\n", time.Since(startTime))
	return resp, err
}

func getRole(req *logical.Request, b logical.Backend, t *testing.T, roleName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"type": "jwt",
	}

	req.Operation = logical.ReadOperation
	req.Path = fmt.Sprintf("role/%s", roleName)
	req.Data = data

	startTime := time.Now()
	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("'Test get role' took %s\n", time.Since(startTime))
	return resp, err
}

func deleteRole(req *logical.Request, b logical.Backend, t *testing.T, roleName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"type": "jwt",
	}

	req.Operation = logical.ReadOperation
	req.Path = fmt.Sprintf("role/%s", roleName)
	req.Data = data

	startTime := time.Now()
	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("'Test delete role' took %s\n", time.Since(startTime))
	return resp, err
}
