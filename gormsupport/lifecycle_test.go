package gormsupport_test

import (
	"github.com/codeready-toolchain/sandbox-auth/gormsupport"
	"github.com/codeready-toolchain/sandbox-auth/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestLifecycleEqual(t *testing.T) {
	t.Parallel()
	test.Require(t, test.UnitTest)

	// Ensure Lifecyle implements the Equaler interface
	var _ gormsupport.Equaler = gormsupport.Lifecycle{}
	var _ gormsupport.Equaler = (*gormsupport.Lifecycle)(nil)

	now := time.Now()
	nowPlus := time.Now().Add(time.Duration(1000))

	a := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: gorm.DeletedAt{},
	}

	// Test for type difference
	b := gormsupport.DummyEqualer{}
	assert.False(t, a.Equal(b))

	// Test CreateAt difference
	c := gormsupport.Lifecycle{
		CreatedAt: nowPlus,
		UpdatedAt: now,
		DeletedAt: gorm.DeletedAt{},
	}
	assert.False(t, a.Equal(c))

	// Test UpdatedAt difference
	d := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: nowPlus,
		DeletedAt: gorm.DeletedAt{},
	}
	assert.False(t, a.Equal(d))

	deletedAtNow := gorm.DeletedAt{}
	require.NoError(t, deletedAtNow.Scan(now))

	deletedAtNowPlus := gorm.DeletedAt{}
	require.NoError(t, deletedAtNowPlus.Scan(nowPlus))

	// Test DeletedAt (one is not nil, the other is) difference
	e := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: deletedAtNow,
	}
	assert.False(t, a.Equal(e))

	// Test DeletedAt (both are not nil) difference
	g := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: nowPlus,
		DeletedAt: deletedAtNow,
	}
	h := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: nowPlus,
		DeletedAt: deletedAtNowPlus,
	}
	assert.False(t, g.Equal(h))

	// Test two lifecycles are equal
	i := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: gorm.DeletedAt{},
	}
	assert.True(t, a.Equal(i))
}
