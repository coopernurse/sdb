package sdb

import (
	"fmt"
	"os"
	"testing"
)

const TestDomain = "testing"

var (
	akey string
	skey string
	db   SimpleDB
)

func init() {
	akey = os.Getenv("AWS_ACCESS_KEY_ID")
	skey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	if akey == "" {
		fmt.Fprintln(os.Stdout, "Environment parameter AWS_ACCESS_KEY is not set, can not connect to SimpleDB, read about AWS authentication on the AWS homepage")
		os.Exit(-1)
	}
	if skey == "" {
		fmt.Fprintln(os.Stdout, "Environment parameter AWS_SECRET_ACCESS_KEY is not set, can not connect to SimpleDB, read about AWS authentication on the AWS homepage")
		os.Exit(-2)
	}
}

func doLog(t *testing.T) {
	t.Log(db.RawRequest)
	t.Log(db.RawResponse)
}

func TestNewSimpleDB(t *testing.T) {
	db = NewSimpleDB(akey, skey, SDBRegionEUWest1)
}

func TestCreateDomain(t *testing.T) {
	_, err := db.CreateDomain(TestDomain)
	doLog(t)
	if err != nil {
		t.Error(err)
	}
}

func TestCreateDomainMissingDomainName(t *testing.T) {
	_, err := db.CreateDomain("")
	doLog(t)
	if err == nil {
		t.Error("Attempting to create domain with empty name should result in an error")
	}
	switch v := err.(type) {
	default:
		t.Error(err)
	case SimpleDBError:
		if v.Code != "InvalidParameterValue" {
			t.Error(v)
		}
	}
}

func TestDomainMetadata(t *testing.T) {
	_, err := db.DomainMetadata(TestDomain)
	doLog(t)
	if err != nil {
		t.Error(err)
	}
}

func TestDeleteDomain(t *testing.T) {
	_, err := db.DeleteDomain(TestDomain)
	doLog(t)
	if err != nil {
		t.Error(err)
	}
}

func TestDeleteDomainMissingDomainName(t *testing.T) {
	_, err := db.DeleteDomain("")
	doLog(t)
	if err == nil {
		t.Error("Attempting to create domain with empty name should result in an error")
	}
	switch v := err.(type) {
	default:
		t.Error(err)
	case SimpleDBError:
		if v.Code != "InvalidParameterValue" {
			t.Error(v)
		}
	}
}
