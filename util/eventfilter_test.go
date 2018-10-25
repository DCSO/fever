package util

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"testing"
)

func TestEventFilterEmpty(t *testing.T) {
	PrepareEventFilter([]string{}, false)
	if AllowType("foo") {
		t.Fail()
	}
	if len(GetAllowedTypes()) > 0 {
		t.Fail()
	}
}

func TestEventFilterEmptyForwardAllSelected(t *testing.T) {
	PrepareEventFilter([]string{"foo", "bar"}, false)
	if !AllowType("foo") {
		t.Fatal("foo not allowed")
	}
	if !AllowType("bar") {
		t.Fatal("bar not allowed")
	}
	if AllowType("baz") {
		t.Fatal("baz allowed but shouldn't be")
	}
	if len(GetAllowedTypes()) != 2 {
		t.Fail()
	}
}

func TestEventFilterEmptyForwardAllSelectedDuplicate(t *testing.T) {
	PrepareEventFilter([]string{"foo", "foo"}, false)
	if !AllowType("foo") {
		t.Fatal("foo not allowed")
	}
	if AllowType("bar") {
		t.Fatal("bar allowed but shouldn't be")
	}
	if AllowType("baz") {
		t.Fatal("baz allowed but shouldn't be")
	}
	if len(GetAllowedTypes()) != 1 {
		t.Fail()
	}
}

func TestEventFilterEmptyForwardAll(t *testing.T) {
	PrepareEventFilter([]string{}, true)
	if !AllowType("foo") {
		t.Fail()
	}
	if len(GetAllowedTypes()) > 0 {
		t.Fail()
	}
}
