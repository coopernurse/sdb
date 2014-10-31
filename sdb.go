package sdb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SDB_REGION_EU_WEST_1 string = "sdb.eu-west-1.amazonaws.com"
	DATE_FORMAT          string = "2006-01-02T15:04:05-07:00"
)

var (
	accessKey string
	secretKey string
	region    string
)

type parameters map[string]string

type Error struct {
	Code    string `xml:"Error>Code"`
	Message string `xml:"Error>Message"`
}

type Response struct {
	Errors    []Error
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
	p           url.Values
	accessKey   string
	secretKey   string
	region      string
	Error       Response
	RawResponse string
	RawRequest  string
}

// Internal methods used for communication

func (sdb *SimpleDB) sign(s string) string {
	mac := hmac.New(sha256.New, []byte(sdb.secretKey))
	mac.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (sdb *SimpleDB) resetParameters() {
	sdb.Error = Response{}
	sdb.RawRequest = ""
	sdb.RawResponse = ""
	sdb.p = make(url.Values)

	sdb.p.Add("AWSAccessKeyId", sdb.accessKey)
	sdb.p.Add("SignatureMethod", "HmacSHA256")
	sdb.p.Add("SignatureVersion", "2")
	sdb.p.Add("Version", "2009-04-15")

	var t time.Time
	t = time.Now().UTC()
	sdb.p.Add("Timestamp", t.Format(DATE_FORMAT))
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
		sdb.Error = v
		return errors.New("Error occured, see SimpleDB.Error for details")
	}

	err = sdb.unmarshal(r, v)

	return
}

// Attributes
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
func NewSimpleDB(a string, s string, r string) *SimpleDB {
	sdb := &SimpleDB{accessKey: a, secretKey: s, region: r}

	sdb.resetParameters()

	return sdb
}

// Commands

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

func (sdb *SimpleDB) DeleteAttributes(domain string, itemName string) (r DeleteAttributesResponse, err error) {
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

type SDBWriter struct {
	sdb    *SimpleDB
	Domain string
	m      sync.Mutex
	buffer []Item
}

func NewSDBWriter(sdb *SimpleDB, domain string) (sw *SDBWriter, err error) {
	_, err = sdb.CreateDomain(domain)
	if err != nil {
		return
	}
	return &SDBWriter{sdb: sdb, Domain: domain}, err
}

func (s *SDBWriter) Write(p []byte) (n int, err error) {
	s.m.Lock()
	defer s.m.Unlock()
	t := time.Now().UTC()
	name := strconv.FormatInt(t.Unix(), 10) + "." + strconv.Itoa(t.Nanosecond())
	i := Item{Name: name}
	i.AddAttribute("msg", strings.TrimSpace(string(p)))

	s.buffer = append(s.buffer, i)
	if len(s.buffer) == 25 {
		tmp := make([]Item, len(s.buffer))
		copy(tmp, s.buffer)
		go func() {
			_, err = s.sdb.BatchPutAttributes(s.Domain, tmp)
			if err != nil {
				log.Println(err)
			}
		}()
		s.buffer = []Item{}
	}

	n = len(p)
	return
}
