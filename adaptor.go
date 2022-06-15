package adaptor

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type Adaptor struct {
	authn.Keychain
}

func (a Adaptor) Credential(ctx context.Context, registry string) (auth.Credential, error) {
	authenticator, err := a.Keychain.Resolve(resource{registry})
	if err != nil {
		return auth.EmptyCredential, err
	}
	authConfig, err := authenticator.Authorization()
	if err != nil {
		return auth.EmptyCredential, err
	}
	if authConfig.Auth != "" {
		c, err := base64.StdEncoding.DecodeString(authConfig.Auth)
		if err != nil {
			return auth.EmptyCredential, err
		}
		cs := string(c)
		username, password, ok := strings.Cut(cs, ":")
		if !ok {
			return auth.EmptyCredential, errors.New("invalid auth")
		}
		authConfig.Username = username
		authConfig.Password = password
	}
	return auth.Credential{
		Username:     authConfig.Username,
		Password:     authConfig.Password,
		RefreshToken: authConfig.IdentityToken,
		AccessToken:  authConfig.RegistryToken,
	}, nil
}

type resource struct {
	registry string
}

func (r resource) String() string {
	return r.RegistryStr()
}

func (r resource) RegistryStr() string {
	return r.registry
}
