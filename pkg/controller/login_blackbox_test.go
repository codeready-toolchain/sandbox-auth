package controller

import (
	"github.com/codeready-toolchain/sandbox-auth/test"
	"github.com/stretchr/testify/suite"
	"testing"
)

type LoginControllerTestSuite struct {
	test.UnitTestSuite
}

func TestLoginController(t *testing.T) {
	suite.Run(t, &LoginControllerTestSuite{UnitTestSuite: test.UnitTestSuite{}})
}
