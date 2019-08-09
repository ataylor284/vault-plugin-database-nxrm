package nxrm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
)

type ClientConfig struct {
	Username, Password, BaseURL string
}

func NewClient(config *ClientConfig) (*Client, error) {
	client := retryablehttp.NewClient()
	return &Client{
		username: config.Username,
		password: config.Password,
		baseURL:  config.BaseURL,
		client:   client,
	}, nil
}

type Client struct {
	username, password, baseURL string
	client                      *retryablehttp.Client
}

type User struct {
	UserId       string   `json:"userId"`
	FirstName    string   `json:"firstName"`
	LastName     string   `json:"lastName"`
	EmailAddress string   `json:"emailAddress"`
	Status       string   `json:"status"`
	Password     string   `json:"password"` // Passwords must be at least 6 characters long.
	Roles        []string `json:"roles"`
}

func (c *Client) GetUser(ctx context.Context, name string) (map[string]interface{}, error) {
	endpoint := "/service/rest/beta/security/users"
	method := http.MethodGet

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	var users []map[string]interface{}
	if err := c.do(ctx, req, &users); err != nil {
		return nil, err
	}
	return users[0], nil
}

func (c *Client) CreateUser(ctx context.Context, name string, user *User) error {
	endpoint := "/service/rest/beta/security/users"
	method := http.MethodPost

	userJson, err := json.Marshal(user)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(userJson))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) ChangePassword(ctx context.Context, name, newPassword string) error {
	endpoint := "/service/rest/beta/security/users/" + name + "/change-password"
	method := http.MethodPut

	req, err := http.NewRequest(method, c.baseURL+endpoint, strings.NewReader(newPassword))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) DeleteUser(ctx context.Context, name string) error {
	endpoint := "/service/rest/beta/security/users/" + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) do(ctx context.Context, req *http.Request, ret interface{}) error {
	retryableReq, err := retryablehttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return err
	}
	retryableReq.SetBasicAuth(c.username, c.password)
	retryableReq.Header.Add("Content-Type", "application/json")

	resp, err := c.client.Do(retryableReq.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if ret == nil {
			return nil
		}
		if err := json.Unmarshal(body, ret); err != nil {
			return fmt.Errorf("%s; %d: %s", err, resp.StatusCode, body)
		}
		return nil
	}

	if resp.StatusCode == 404 {
		return nil
	}

	return fmt.Errorf("%d: %s", resp.StatusCode, body)
}
