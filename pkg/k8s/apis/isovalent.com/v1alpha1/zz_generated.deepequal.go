//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepequal-gen. DO NOT EDIT.

package v1alpha1

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentFQDNGroupSpec) DeepEqual(other *IsovalentFQDNGroupSpec) bool {
	if other == nil {
		return false
	}

	if ((in.FQDNs != nil) && (other.FQDNs != nil)) || ((in.FQDNs == nil) != (other.FQDNs == nil)) {
		in, other := &in.FQDNs, &other.FQDNs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}