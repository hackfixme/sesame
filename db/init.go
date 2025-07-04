package db

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/nacl/box"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/db/types"
)

func createRoles(ctx context.Context, d types.Querier) (map[string]*models.Role, error) {
	roles := []*models.Role{
		{
			Name: "admin",
			Permissions: []models.Permission{
				{
					Namespaces: map[string]struct{}{"*": {}},
					Actions:    map[models.Action]struct{}{models.ActionAny: {}},
					Target:     models.PermissionTarget{Resource: models.ResourceAny},
				},
			},
		},
		{
			Name: "node",
			Permissions: []models.Permission{
				{
					Namespaces: map[string]struct{}{"*": {}},
					Actions:    map[models.Action]struct{}{models.ActionRead: {}},
					Target: models.PermissionTarget{
						Resource: models.ResourceStore,
						Patterns: []string{"*"},
					},
				},
			},
		},
		{
			Name: "user",
			Permissions: []models.Permission{
				{
					Namespaces: map[string]struct{}{"*": {}},
					Actions:    map[models.Action]struct{}{models.ActionAny: {}},
					Target: models.PermissionTarget{
						Resource: models.ResourceStore,
						Patterns: []string{"*"},
					},
				},
			},
		},
	}
	rolesMap := map[string]*models.Role{}
	for _, role := range roles {
		if err := role.Save(ctx, d, false); err != nil {
			return nil, err
		}
		rolesMap[role.Name] = role
	}

	return rolesMap, nil
}

func createLocalUser(ctx context.Context, d types.Querier, role *models.Role) (*models.User, error) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating encryption key pair: %w", err)
	}

	pkHash := crypto.Hash("", pubKey[:])
	user := &models.User{
		Name:       base58.Encode(pkHash[:8]),
		Type:       models.UserTypeLocal,
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Roles:      []*models.Role{role},
	}
	if err := user.Save(ctx, d, false); err != nil {
		return nil, err
	}

	return user, nil
}
