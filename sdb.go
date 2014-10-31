// Copyright (c) 2014, Roland Bali (roland.bali@spagettikod.se), Spagettikod
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this
//    list of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may
//    be used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package sdb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SDBRegionEUWest1 string = "sdb.eu-west-1.amazonaws.com"
)

var (
	accessKey  string
	secretKey  string
	region     string
	dateFormat string = "2006-01-02T15:04:05-07:00"
)

type parameters map[string]string

type SimpleDBError struct {
	Code      string `xml:"Error>Code"`
	Message   string `xml:"Error>Message"`
	RequestId string
}

type Response struct {
	Errors    []SimpleDBError
	RequestId string
}

type ResponseMetadata struct {
	RequestId string
	BoxUsage  float64
}

type DeleteDomainResponse struct {
	ResponseMetadata ResponseMetadata
}

type CreateDomainResponse struct {
	ResponseMetadata ResponseMetadata
}

type ListDomainsResponse struct {
	DomainNames      []string `xml:"ListDomainsResult>DomainName"`
	ResponseMetadata ResponseMetadata
}

type DomainMetadataResponse struct {
	ItemCount                int64 `xml:"DomainMetadataResult>ItemCount"`
	ItemNamesSizeBytes       int64 `xml:"DomainMetadataResult>ItemNamesSizeBytes"`
	AttributeNameCount       int64 `xml:"DomainMetadataResult>AttributeNameCount"`
	AttributeNamesSizeBytes  int64 `xml:"DomainMetadataResult>AttributeNamesSizeBytes"`
	AttributeValueCount      int64 `xml:"DomainMetadataResult>AttributeValueCount"`
	AttributeValuesSizeBytes int64 `xml:"DomainMetadataResult>AttributeValuesSizeBytes"`
	Timestamp                int64 `xml:"DomainMetadataResult>Timestamp"`
	ResponseMetadata         ResponseMetadata
}

type PutAttributesResponse struct {
	ResponseMetadata ResponseMetadata
}

type GetAttributesResponse struct {
	Attributes []Attribute `xml:"GetAttributesResult>Attribute"`
}

type DeleteAttributesResponse struct {
	ResponseMetadata ResponseMetadata
}

type SelectResponse struct {
	Items []Item `xml:"SelectResult>Item"`
}

type Attribute struct {
	Name    string
	Value   string
	Replace bool
}

type Item struct {
	Name       string
	Attributes []Attribute `xml:"Attribute"`
}

type SimpleDB struct {
	RawResponse string
	RawRequest  string
	p           url.Values
	accessKey   string
	secretKey   string
	region      string
}

func (err SimpleDBError) Error() string {
	return err.Code + ": " + err.Message
}

func (sdb *SimpleDB) sign(s string) string {
	mac := hmac.New(sha256.New, []byte(sdb.secretKey))
	mac.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (sdb *SimpleDB) resetParameters() {
	sdb.RawRequest = ""
	sdb.RawResponse = ""
	sdb.p = make(url.Values)

	sdb.p.Add("AWSAccessKeyId", sdb.accessKey)
	sdb.p.Add("SignatureMethod", "HmacSHA256")
	sdb.p.Add("SignatureVersion", "2")
	sdb.p.Add("Version", "2009-04-15")

	var t time.Time
	t = time.Now().UTC()
	sdb.p.Add("Timestamp", t.Format(dateFormat))
}

func (sdb *SimpleDB) unmarshal(r *http.Response, v interface{}) (err error) {
	var b []byte
	b, err = ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	sdb.RawResponse = string(b)
	err = xml.Unmarshal(b, &v)
	return
}

func (sdb *SimpleDB) post(v interface{}) (err error) {
	unsignedSignature := "POST\n" + sdb.region + "\n" + "/\n" + strings.Replace(sdb.p.Encode(), "+", "%20", -1)

	sdb.p.Add("Signature", sdb.sign(unsignedSignature))

	sdb.RawRequest = sdb.p.Encode()
	sdb.RawRequest = strings.Replace(sdb.RawRequest, "+", "%20", -1)

	var r *http.Response
	r, err = http.Post("https://"+sdb.region, "application/x-www-form-urlencoded; charset=utf-8", strings.NewReader(sdb.RawRequest))
	if err != nil {
		return
	}

	if r.StatusCode != 200 {
		var v Response
		err = sdb.unmarshal(r, &v)
		if err != nil {
			return
		}
		if len(v.Errors) > 0 {
			return SimpleDBError{Code: v.Errors[0].Code, Message: v.Errors[0].Message, RequestId: v.Errors[0].RequestId}
		} else {
			return errors.New(r.Status)
		}
	}

	err = sdb.unmarshal(r, v)

	return
}

func NewAttribute(name string, value string) *Attribute {
	a := &Attribute{Name: name, Value: value, Replace: false}
	return a
}

func NewItem(name string) *Item {
	i := &Item{Name: name}
	return i
}

func (i *Item) AddAttribute(name string, value string) *Attribute {
	a := &Attribute{Name: name, Value: value, Replace: false}
	i.Attributes = append(i.Attributes, *a)
	return a
}

func (i *Item) RemoveAttribute(a Attribute) Attribute {
	var removedAttr Attribute
	attrs := i.Attributes
	i.Attributes = []Attribute{}
	for _, attr := range attrs {
		if attr.Name != a.Name && attr.Value != a.Value {
			i.Attributes = append(i.Attributes, attr)
		} else {
			removedAttr = attr
		}
	}
	return removedAttr
}

// Constructor
func NewSimpleDB(a string, s string, r string) SimpleDB {
	sdb := SimpleDB{accessKey: a, secretKey: s, region: r}

	sdb.resetParameters()

	return sdb
}

func (sdb *SimpleDB) ListDomains() (r ListDomainsResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "ListDomains")

	err = sdb.post(&r)

	return
}

func (sdb *SimpleDB) DomainMetadata(name string) (r DomainMetadataResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "DomainMetadata")
	sdb.p.Add("DomainName", name)

	err = sdb.post(&r)

	return
}

func (sdb *SimpleDB) CreateDomain(name string) (r CreateDomainResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "CreateDomain")
	sdb.p.Add("DomainName", name)

	err = sdb.post(&r)

	return
}

func (sdb *SimpleDB) DeleteDomain(name string) (r DeleteDomainResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "DeleteDomain")
	sdb.p.Add("DomainName", name)

	err = sdb.post(&r)

	return
}

func (sdb *SimpleDB) PutAttributes(domain string, i *Item) (r PutAttributesResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "PutAttributes")
	sdb.p.Add("DomainName", domain)
	sdb.p.Add("ItemName", i.Name)

	for i, a := range i.Attributes {
		o := strconv.Itoa(i + 1)
		sdb.p.Add("Attribute."+o+".Name", a.Name)
		sdb.p.Add("Attribute."+o+".Value", a.Value)
	}

	err = sdb.post(&r)
	return
}

func (sdb *SimpleDB) BatchPutAttributes(domain string, items []Item) (r PutAttributesResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "BatchPutAttributes")
	sdb.p.Add("DomainName", domain)

	for i, item := range items {
		itemNo := strconv.Itoa(i + 1)
		sdb.p.Add("Item."+itemNo+".ItemName", item.Name)
		for j, a := range item.Attributes {
			o := strconv.Itoa(j + 1)
			sdb.p.Add("Item."+itemNo+".Attribute."+o+".Name", a.Name)
			sdb.p.Add("Item."+itemNo+".Attribute."+o+".Value", a.Value)
		}
	}

	err = sdb.post(&r)
	return
}

func (sdb *SimpleDB) GetAttributes(domain string, itemName string) (r GetAttributesResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "GetAttributes")
	sdb.p.Add("DomainName", domain)
	sdb.p.Add("ItemName", itemName)

	err = sdb.post(&r)

	return
}

func (sdb *SimpleDB) DeleteItem(domain string, itemName string) (r DeleteAttributesResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "DeleteAttributes")
	sdb.p.Add("DomainName", domain)
	sdb.p.Add("ItemName", itemName)

	err = sdb.post(&r)

	return
}

func (sdb *SimpleDB) Select(q string) (r SelectResponse, err error) {
	sdb.resetParameters()

	sdb.p.Add("Action", "Select")
	sdb.p.Add("SelectExpression", q)

	err = sdb.post(&r)

	return
}
