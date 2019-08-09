package nxrm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
)

func New() (interface{}, error) {
	db := NewNxrm()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues), nil
}

func Run(apiTLSConfig *api.TLSConfig) error {
	dbplugin.Serve(NewNxrm(), api.VaultPluginTLSProvider(apiTLSConfig))
	return nil
}

func NewNxrm() *Nxrm {
	return &Nxrm{
		credentialProducer: &credsutil.SQLCredentialsProducer{
			DisplayNameLen: 15,
			RoleNameLen:    15,
			UsernameLen:    100,
			Separator:      "-",
		},
	}
}

type Nxrm struct {
	credentialProducer credsutil.CredentialsProducer
	mux                sync.RWMutex
	config             map[string]interface{}
}

func (nxrm *Nxrm) Type() (string, error) {
	return "nxrm", nil
}

func (nxrm *Nxrm) SecretValues() map[string]interface{} {
	nxrm.mux.RLock()
	defer nxrm.mux.RUnlock()

	replacements := make(map[string]interface{})
	for _, secretKey := range []string{"password", "client_key"} {
		vIfc, found := nxrm.config[secretKey]
		if !found {
			continue
		}
		secretVal, ok := vIfc.(string)
		if !ok {
			continue
		}
		replacements[secretVal] = "[" + secretKey + "]"
	}
	return replacements
}

func (nxrm *Nxrm) Init(ctx context.Context, config map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	for _, requiredField := range []string{"username", "password", "url"} {
		raw, ok := config[requiredField]
		if !ok {
			return nil, fmt.Errorf(`%q must be provided`, requiredField)
		}
		if _, ok := raw.(string); !ok {
			return nil, fmt.Errorf(`%q must be a string`, requiredField)
		}
	}

	for _, optionalField := range []string{"ca_cert", "ca_path", "client_cert", "client_key", "tls_server_name"} {
		raw, ok := config[optionalField]
		if !ok {
			continue
		}
		if _, ok = raw.(string); !ok {
			return nil, fmt.Errorf(`%q must be a string`, optionalField)
		}
	}

	if raw, ok := config["insecure"]; ok {
		if _, ok = raw.(bool); !ok {
			return nil, errors.New(`"insecure" must be a bool`)
		}
	}

	client, err := buildClient(config)
	if err != nil {
		return nil, errwrap.Wrapf("couldn't make client with inbound config: {{err}}", err)
	}

	if verifyConnection {
		if _, err := client.GetUser(ctx, "admin"); err != nil {
			return nil, errwrap.Wrapf("client test of getting a user failed: {{err}}", err)
		}
	}

	nxrm.mux.Lock()
	defer nxrm.mux.Unlock()
	nxrm.config = config
	return nxrm.config, nil
}

func (nxrm *Nxrm) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, _ time.Time) (string, string, error) {
	username, err := nxrm.credentialProducer.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", errwrap.Wrapf(fmt.Sprintf("unable to generate username for %q: {{err}}", usernameConfig), err)
	}

	password, err := nxrm.credentialProducer.GeneratePassword()
	if err != nil {
		return "", "", errwrap.Wrapf("unable to generate password: {{err}}", err)
	}

	stmt, err := newCreationStatement(statements)
	if err != nil {
		return "", "", errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	user := &User{
		UserId:       username,
		FirstName:    "vault user",
		LastName:     "vault user",
		EmailAddress: "vaultuser@example.com",
		Status:       "active",
		Password:     password,
		Roles:        stmt.NxrmRoles,
	}

	nxrm.mux.RLock()
	defer nxrm.mux.RUnlock()

	client, err := buildClient(nxrm.config)
	if err != nil {
		return "", "", errwrap.Wrapf("unable to get client: {{err}}", err)
	}
	if err := client.CreateUser(ctx, username, user); err != nil {
		return "", "", errwrap.Wrapf(fmt.Sprintf("unable to create user name %s, user %q: {{err}}", username, user), err)
	}
	return username, password, nil
}

func (nxrm *Nxrm) RenewUser(_ context.Context, _ dbplugin.Statements, _ string, _ time.Time) error {
	// FIXME
	return nil
}

func (nxrm *Nxrm) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	nxrm.mux.RLock()
	defer nxrm.mux.RUnlock()

	client, err := buildClient(nxrm.config)
	if err != nil {
		return errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	var errs error
	if err := client.DeleteUser(ctx, username); err != nil {
		errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to create user name %s: {{err}}", username), err))
	}
	return errs
}

func (nxrm *Nxrm) RotateRootCredentials(ctx context.Context, _ []string) (map[string]interface{}, error) {
	newPassword, err := nxrm.credentialProducer.GeneratePassword()
	if err != nil {
		return nil, errwrap.Wrapf("unable to generate root password: {{err}}", err)
	}

	nxrm.mux.Lock()
	defer nxrm.mux.Unlock()

	client, err := buildClient(nxrm.config)
	if err != nil {
		return nil, errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	if err := client.ChangePassword(ctx, nxrm.config["username"].(string), newPassword); err != nil {
		return nil, errwrap.Wrapf("unable to change password: {{}}", err)
	}

	nxrm.config["password"] = newPassword
	return nxrm.config, nil
}

func (nxrm *Nxrm) Close() error {
	return nil
}

func (nxrm *Nxrm) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := nxrm.Init(ctx, config, verifyConnection)
	return err
}

func newCreationStatement(statements dbplugin.Statements) (*creationStatement, error) {
	if len(statements.Creation) == 0 {
		return nil, dbutil.ErrEmptyCreationStatement
	}
	stmt := &creationStatement{}
	if err := json.Unmarshal([]byte(statements.Creation[0]), stmt); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to unmarshal %s: {{err}}", []byte(statements.Creation[0])), err)
	}
	return stmt, nil
}

type creationStatement struct {
	NxrmRoles []string `json:"nxrm-roles"`
}

func buildClient(config map[string]interface{}) (*Client, error) {
	clientConfig := &ClientConfig{
		Username: config["username"].(string),
		Password: config["password"].(string),
		BaseURL:  config["url"].(string),
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (nxrm *Nxrm) GenerateCredentials(ctx context.Context) (string, error) {
	password, err := nxrm.credentialProducer.GeneratePassword()
	if err != nil {
		return "", err
	}
	return password, nil
}

func (nxrm *Nxrm) SetCredentials(ctx context.Context, statements dbplugin.Statements, staticConfig dbplugin.StaticUserConfig) (username string, password string, err error) {
	return "", "", dbutil.Unimplemented()
}
