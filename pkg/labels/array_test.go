// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
)

var _ = Suite(&LabelsSuite{})

func (s *LabelsSuite) TestMatches(c *C) {
	a := LabelArray{
		NewLabel("1", "1", "1"),
		NewLabel("2", "2", "1"),
		NewLabel("3", "3", "1"),
	}
	b := LabelArray{
		NewLabel("1", "1", "1"),
		NewLabel("2", "2", "1"),
	}
	empty := LabelArray{}

	c.Assert(a.Contains(b), Equals, true)      // b is in a
	c.Assert(b.Contains(a), Equals, false)     // a is NOT in b
	c.Assert(a.Contains(empty), Equals, true)  // empty is in a
	c.Assert(b.Contains(empty), Equals, true)  // empty is in b
	c.Assert(empty.Contains(a), Equals, false) // a is NOT in empty
}

func (s *LabelsSuite) TestParse(c *C) {
	c.Assert(ParseLabelArray(), checker.DeepEquals, LabelArray{})
	c.Assert(ParseLabelArray("magic"), checker.DeepEquals, LabelArray{ParseLabel("magic")})
	// LabelArray is sorted
	c.Assert(ParseLabelArray("a", "c", "b"), checker.DeepEquals,
		LabelArray{ParseLabel("a"), ParseLabel("b"), ParseLabel("c")})
	// NewLabelArrayFromSortedList
	c.Assert(NewLabelArrayFromSortedList("unspec:a=;unspec:b;unspec:c=d"), checker.DeepEquals,
		LabelArray{ParseLabel("a"), ParseLabel("b"), ParseLabel("c=d")})
}

func (s *LabelsSuite) TestHas(c *C) {
	lbls := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	var hasTests = []struct {
		input    string // input
		expected bool   // expected result
	}{
		{"", false},
		{"any", false},
		{"env", true},
		{"container.env", false},
		{"container:env", false},
		{"any:env", false},
		{"any.env", true},
		{"any:user", false},
		{"any.user", true},
		{"user", true},
		{"container.user", true},
		{"container:bob", false},
	}
	for _, tt := range hasTests {
		c.Logf("has %q?", tt.input)
		c.Assert(lbls.Has(tt.input), Equals, tt.expected)
	}
}

func (s *LabelsSuite) TestEquals(c *C) {
	lbls1 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	lbls2 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	lbls3 := LabelArray{
		NewLabel("user", "bob", LabelSourceContainer),
		NewLabel("env", "devel", LabelSourceAny),
	}
	lbls4 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
	}
	lbls5 := LabelArray{
		NewLabel("env", "prod", LabelSourceAny),
	}
	lbls6 := LabelArray{}

	c.Assert(lbls1.Equals(lbls1), Equals, true)
	c.Assert(lbls1.Equals(lbls2), Equals, true)
	c.Assert(lbls1.Equals(lbls3), Equals, false) // inverted order
	c.Assert(lbls1.Equals(lbls4), Equals, false) // different count
	c.Assert(lbls1.Equals(lbls5), Equals, false)
	c.Assert(lbls1.Equals(lbls6), Equals, false)

	c.Assert(lbls2.Equals(lbls1), Equals, true)
	c.Assert(lbls2.Equals(lbls2), Equals, true)
	c.Assert(lbls2.Equals(lbls3), Equals, false) // inverted order
	c.Assert(lbls2.Equals(lbls4), Equals, false) // different count
	c.Assert(lbls2.Equals(lbls5), Equals, false)
	c.Assert(lbls2.Equals(lbls6), Equals, false)

	c.Assert(lbls3.Equals(lbls1), Equals, false)
	c.Assert(lbls3.Equals(lbls2), Equals, false)
	c.Assert(lbls3.Equals(lbls3), Equals, true)
	c.Assert(lbls3.Equals(lbls4), Equals, false)
	c.Assert(lbls3.Equals(lbls5), Equals, false)
	c.Assert(lbls3.Equals(lbls6), Equals, false)

	c.Assert(lbls4.Equals(lbls1), Equals, false)
	c.Assert(lbls4.Equals(lbls2), Equals, false)
	c.Assert(lbls4.Equals(lbls3), Equals, false)
	c.Assert(lbls4.Equals(lbls4), Equals, true)
	c.Assert(lbls4.Equals(lbls5), Equals, false)
	c.Assert(lbls4.Equals(lbls6), Equals, false)

	c.Assert(lbls5.Equals(lbls1), Equals, false)
	c.Assert(lbls5.Equals(lbls2), Equals, false)
	c.Assert(lbls5.Equals(lbls3), Equals, false)
	c.Assert(lbls5.Equals(lbls4), Equals, false)
	c.Assert(lbls5.Equals(lbls5), Equals, true)
	c.Assert(lbls5.Equals(lbls6), Equals, false)

	c.Assert(lbls6.Equals(lbls1), Equals, false)
	c.Assert(lbls6.Equals(lbls2), Equals, false)
	c.Assert(lbls6.Equals(lbls3), Equals, false)
	c.Assert(lbls6.Equals(lbls4), Equals, false)
	c.Assert(lbls6.Equals(lbls5), Equals, false)
	c.Assert(lbls6.Equals(lbls6), Equals, true)
}

func (s *LabelsSuite) TestLess(c *C) {
	// lbls1-lbls8 are defined in lexical order
	lbls1 := LabelArray(nil)
	lbls2 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
	}
	lbls3 := LabelArray{
		NewLabel("env", "devel", LabelSourceReserved),
	}
	lbls4 := LabelArray{
		NewLabel("env", "prod", LabelSourceAny),
	}
	lbls5 := LabelArray{
		NewLabel("env", "prod", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	lbls6 := LabelArray{
		NewLabel("env", "prod", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	lbls7 := LabelArray{
		NewLabel("env", "prod", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
		NewLabel("xyz", "", LabelSourceAny),
	}
	lbls8 := LabelArray{
		NewLabel("foo", "bar", LabelSourceAny),
	}

	c.Assert(lbls1.Less(lbls1), Equals, false)
	c.Assert(lbls1.Less(lbls2), Equals, true)
	c.Assert(lbls1.Less(lbls3), Equals, true)
	c.Assert(lbls1.Less(lbls4), Equals, true)
	c.Assert(lbls1.Less(lbls5), Equals, true)
	c.Assert(lbls1.Less(lbls6), Equals, true)
	c.Assert(lbls1.Less(lbls7), Equals, true)
	c.Assert(lbls1.Less(lbls8), Equals, true)

	c.Assert(lbls2.Less(lbls1), Equals, false)
	c.Assert(lbls2.Less(lbls2), Equals, false)
	c.Assert(lbls2.Less(lbls3), Equals, true)
	c.Assert(lbls2.Less(lbls4), Equals, true)
	c.Assert(lbls2.Less(lbls5), Equals, true)
	c.Assert(lbls2.Less(lbls6), Equals, true)
	c.Assert(lbls2.Less(lbls7), Equals, true)
	c.Assert(lbls2.Less(lbls8), Equals, true)

	c.Assert(lbls3.Less(lbls1), Equals, false)
	c.Assert(lbls3.Less(lbls2), Equals, false)
	c.Assert(lbls3.Less(lbls3), Equals, false)
	c.Assert(lbls3.Less(lbls4), Equals, true)
	c.Assert(lbls3.Less(lbls5), Equals, true)
	c.Assert(lbls3.Less(lbls6), Equals, true)
	c.Assert(lbls3.Less(lbls7), Equals, true)
	c.Assert(lbls3.Less(lbls8), Equals, true)

	c.Assert(lbls4.Less(lbls1), Equals, false)
	c.Assert(lbls4.Less(lbls2), Equals, false)
	c.Assert(lbls4.Less(lbls3), Equals, false)
	c.Assert(lbls4.Less(lbls4), Equals, false)
	c.Assert(lbls4.Less(lbls5), Equals, true)
	c.Assert(lbls4.Less(lbls6), Equals, true)
	c.Assert(lbls4.Less(lbls7), Equals, true)
	c.Assert(lbls4.Less(lbls8), Equals, true)

	c.Assert(lbls5.Less(lbls1), Equals, false)
	c.Assert(lbls5.Less(lbls2), Equals, false)
	c.Assert(lbls5.Less(lbls3), Equals, false)
	c.Assert(lbls5.Less(lbls4), Equals, false)
	c.Assert(lbls5.Less(lbls5), Equals, false)
	c.Assert(lbls5.Less(lbls6), Equals, false)
	c.Assert(lbls5.Less(lbls7), Equals, true)
	c.Assert(lbls5.Less(lbls8), Equals, true)

	c.Assert(lbls6.Less(lbls1), Equals, false)
	c.Assert(lbls6.Less(lbls2), Equals, false)
	c.Assert(lbls6.Less(lbls3), Equals, false)
	c.Assert(lbls6.Less(lbls4), Equals, false)
	c.Assert(lbls6.Less(lbls5), Equals, false)
	c.Assert(lbls6.Less(lbls6), Equals, false)
	c.Assert(lbls6.Less(lbls7), Equals, true)
	c.Assert(lbls6.Less(lbls8), Equals, true)

	c.Assert(lbls7.Less(lbls1), Equals, false)
	c.Assert(lbls7.Less(lbls2), Equals, false)
	c.Assert(lbls7.Less(lbls3), Equals, false)
	c.Assert(lbls7.Less(lbls4), Equals, false)
	c.Assert(lbls7.Less(lbls5), Equals, false)
	c.Assert(lbls7.Less(lbls6), Equals, false)
	c.Assert(lbls7.Less(lbls7), Equals, false)
	c.Assert(lbls7.Less(lbls8), Equals, true)

	c.Assert(lbls8.Less(lbls1), Equals, false)
	c.Assert(lbls8.Less(lbls2), Equals, false)
	c.Assert(lbls8.Less(lbls3), Equals, false)
	c.Assert(lbls8.Less(lbls4), Equals, false)
	c.Assert(lbls8.Less(lbls5), Equals, false)
	c.Assert(lbls8.Less(lbls6), Equals, false)
	c.Assert(lbls8.Less(lbls7), Equals, false)
	c.Assert(lbls8.Less(lbls8), Equals, false)
}

// TestOutputConversions tests the various ways a LabelArray can be converted
// into other representations
func (s *LabelsSuite) TestOutputConversions(c *C) {
	lbls := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
		NewLabel("something", "somethingelse", LabelSourceK8s),
		NewLabel("nosource", "value", ""),
		NewLabel("nosource", "value", "actuallyASource"),
	}

	expectMdl := []string{"any:env=devel", "container:user=bob", "k8s:something=somethingelse", "unspec:nosource=value", "actuallyASource:nosource=value"}
	sort.StringSlice(expectMdl).Sort()
	mdl := lbls.GetModel()
	sort.StringSlice(mdl).Sort()
	c.Assert(len(mdl), Equals, len(expectMdl))
	for i := range mdl {
		c.Assert(mdl[i], Equals, expectMdl[i])
	}

	expectString := "[any:env=devel container:user=bob k8s:something=somethingelse unspec:nosource=value actuallyASource:nosource=value]"
	c.Assert(lbls.String(), Equals, expectString)

	// Note: the two nosource entries do not alias when rendered into the StringMap
	// format, because they have different sources.
	expectMap := map[string]string{
		"any:env":                       "devel",
		"container:user":                "bob",
		"k8s:something":                 "somethingelse",
		LabelSourceUnspec + ":nosource": "value",
		"actuallyASource:nosource":      "value"}
	mp := lbls.StringMap()
	c.Assert(len(mp), Equals, len(expectMap))
	for k, v := range mp {
		c.Assert(v, Equals, expectMap[k])
	}
}

func BenchmarkLabelArray_GetModel(b *testing.B) {
	l := NewLabelArrayFromSortedList("a;b;c;d;e;f;g;h;i;j;k;l;m;n;o;p;q;r;s;t;u;v;w;x;y;z")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.GetModel()
	}
}

func BenchmarkLabelArray_String(b *testing.B) {
	l := NewLabelArrayFromSortedList("a;b;c;d;e;f;g;h;i;j;k;l;m;n;o;p;q;r;s;t;u;v;w;x;y;z")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.String()
	}
}

// LabelArray.Has() is a specific interface
// that is required for kubernetes selectors to work
func TestLabelArray_Has(t *testing.T) {
	lbls := LabelArray{
		NewLabel("foo", "bar", "k8s"),
		NewLabel("foo1", "bar1", "any"), // not valid, but good to capture
		NewLabel("kube-apiserver", "", "reserved"),
	}
	lbls = append(lbls, GetCIDRLabels(netip.MustParsePrefix("10.1.2.0/24")).LabelArray()...)
	lbls = append(lbls, GetCIDRLabels(netip.MustParsePrefix("2001:db8:cafe::/54")).LabelArray()...)
	lbls.Sort()

	for key, expected := range map[string]bool{
		"any.foo":                 true,
		"k8s.foo":                 true,
		"k8s.foo1":                false,
		"reserved.kube-apiserver": true,

		"cidr.10.1.2.0/24": true,  // exact match
		"cidr.10.1.0.0/22": true,  // larger cidr: OK
		"cidr.10.1.2.0/25": false, // smaller cidr: no

		"cidr.2001-db8-cafe--0/54": true,  // exact
		"cidr.2001-db8-cafe--0/53": true,  // larger
		"cidr.2001-db8-cafe--0/55": false, // smaller
	} {
		assert.Equal(t, expected, lbls.Has(key), key)
	}
}

func TestLabelArray_Intersects(t *testing.T) {
	for _, tc := range []struct {
		a    string
		b    string
		want bool
	}{
		{
			"k8s:foo=bar",
			"k8s:foo=bar",
			true,
		},
		{
			"",
			"k8s:foo=bar",
			false,
		},
		{
			"k8s:foo=bar",
			"",
			false,
		},
		{
			"k8s:foo=bar",
			"k8s:foo=baz",
			false,
		},
		{
			"k8s:foo=bar",
			"any:foo=baz",
			false,
		},
		{
			"k8s:a=b k8s:a1=b1 k8s:c=d",
			"k8s:a2=b2 k8s:c=d k8s:e=f",
			true,
		},
		{
			"k8s:foo=bar",
			"any:foo=bar",
			true,
		},
		{
			"any:foo=bar",
			"k8s:foo=bar",
			false,
		},
	} {
		la := ParseLabelArray(strings.Split(tc.a, " ")...)
		lb := ParseLabelArray(strings.Split(tc.b, " ")...)
		assert.Equal(t, tc.want, la.Intersects(lb), "[%s].Intersects([%s])", tc.a, tc.b)

	}

	// Test a careful CIDR case that catches naive sorting
	la := GetCIDRLabels(netip.MustParsePrefix("11.11.11.11/32")).LabelArray()
	lb := ParseLabelArray("cidr:110.0.0.0/8", "cidr:8.0.0.0/5")
	assert.True(t, la.Intersects(lb))

}
