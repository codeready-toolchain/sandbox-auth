package log

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func LogAndAssertJSON(t *testing.T, log func(), assertions func(fields logrus.Fields)) {
	var buffer bytes.Buffer
	var fields logrus.Fields

	InitializeLogger(true, "debug")
	logger.Out = &buffer
	logger.Level = logrus.DebugLevel
	log()

	err := json.Unmarshal(buffer.Bytes(), &fields)
	assert.Nil(t, err)

	assertions(fields)
}

func TestPointerToString(t *testing.T) {
	t.Parallel()
	str := "test"
	assert.Equal(t, "test", PointerToString(&str))
	assert.Equal(t, "<nil>", PointerToString(nil))
}

func TestInfo(t *testing.T) {
	LogAndAssertJSON(t, func() {
		Info(context.Background(), nil, "test")
	}, func(fields logrus.Fields) {
		assert.Equal(t, fields["msg"], "test")
		assert.Equal(t, fields["level"], "info")
		assert.Equal(t, fields["pkg"], "pkg/log.TestInfo")
	})
}

func TestInfoWithFields(t *testing.T) {
	LogAndAssertJSON(t, func() {
		Info(context.Background(), map[string]interface{}{"key": "value"}, "test")
	}, func(fields logrus.Fields) {
		assert.Equal(t, fields["msg"], "test")
		assert.Equal(t, fields["level"], "info")
		assert.Equal(t, fields["key"], "value")
		assert.Equal(t, fields["pkg"], "pkg/log.TestInfoWithFields")
	})
}

func TestWarn(t *testing.T) {
	LogAndAssertJSON(t, func() {
		Warn(context.Background(), nil, "test")
	}, func(fields logrus.Fields) {
		assert.Equal(t, fields["msg"], "test")
		assert.Equal(t, fields["level"], "warning")
	})
}

func TestDebug(t *testing.T) {
	LogAndAssertJSON(t, func() {
		Debug(context.Background(), nil, "test")
	}, func(fields logrus.Fields) {
		assert.Equal(t, fields["msg"], "test")
		assert.Equal(t, fields["level"], "debug")
	})
}

func TestDebugMsgFieldHasPrefix(t *testing.T) {
	LogAndAssertJSON(t, func() {
		Debug(context.Background(), map[string]interface{}{"req": "PUT", "info": "hello"}, "msg with additional fields: %s", "value of my field")
	}, func(fields logrus.Fields) {
		assert.Equal(t, fields["msg"], "msg with additional fields: value of my field")
		assert.Equal(t, fields["req"], "PUT")
		assert.Equal(t, fields["info"], "hello")
	})
}

func TestInfoMsgFieldHasPrefix(t *testing.T) {
	LogAndAssertJSON(t, func() {
		Info(context.Background(), map[string]interface{}{"req": "GET"}, "message with additional fields: %s", "value of my field")
	}, func(fields logrus.Fields) {
		assert.Equal(t, fields["msg"], "message with additional fields: value of my field")
		assert.Equal(t, fields["req"], "GET")
		assert.Equal(t, fields["level"], "info")
	})
}
