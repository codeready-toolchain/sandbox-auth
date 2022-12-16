package controller

import (
	"context"
	"github.com/codeready-toolchain/sandbox-auth/gen/login"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application"
)

type loginController struct {
	app application.Application
}

// NewLoginController returns the login service implementation.
func NewLoginController(app application.Application) login.Service {
	return &loginController{
		app: app,
	}
}

func (l loginController) Login(ctx context.Context, criteria *login.LoginCriteria) (res *login.LoginResult, err error) {
	//TODO implement me
	panic("implement me")
}

func (l loginController) Callback(ctx context.Context, criteria *login.LoginCallbackCriteria) (res *login.LoginResult, err error) {
	//TODO implement me
	panic("implement me")
}
