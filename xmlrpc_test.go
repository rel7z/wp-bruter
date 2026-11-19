package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseMulticall(t *testing.T) {
	body := []byte(`<methodResponse><params><param><value><array><data>
<value><struct><member><name>faultCode</name><value><int>403</int></value></member></struct></value>
<value><struct><member><name>blogid</name><value><string>1</string></value></member></struct></value>
<value><struct><member><name>faultCode</name><value><int>403</int></value></member></struct></value>
</data></array></value></param></params></methodResponse>`)

	hits, ok := parseMulticall(body, 3)
	if !ok {
		t.Fatal("parse rejected a well-formed response")
	}
	want := []bool{false, true, false}
	for i, h := range hits {
		if h.ok != want[i] || h.index != i {
			t.Fatalf("hit %d = %+v, want ok=%v", i, h, want[i])
		}
	}

	if _, ok := parseMulticall(body, 4); ok {
		t.Fatal("short response must be rejected: markers would land on the wrong credential")
	}
}

func TestMulticallBodyIsEscaped(t *testing.T) {
	body := xmlrpcMulticallBody("wp.getUsersBlogs", [][2]string{{"a&b", `p<1>"x"`}})
	if !strings.Contains(body, "<methodName>system.multicall</methodName>") {
		t.Fatal("missing system.multicall")
	}
	if !strings.Contains(body, "a&amp;b") || !strings.Contains(body, "p&lt;1&gt;&quot;x&quot;") {
		t.Fatalf("credentials not escaped: %s", body)
	}
	if strings.Count(body, "<struct>") != 1 {
		t.Fatal("one call expected")
	}
}

// TestMulticallAgainstFake needs a server on 127.0.0.1:8099 (see the README);
// it is skipped when that port is closed.
func TestMulticallAgainstFake(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8099", time.Second)
	if err != nil {
		t.Skip("no fake server on 127.0.0.1:8099")
	}
	conn.Close()

	httpClient = newHTTPClient()
	j := &SiteJob{Site: "http://127.0.0.1:8099", UserAgent: "Mozilla/5.0"}
	j.xmlMethod = "wp.getUsersBlogs"
	j.xmlrpc.Store(true)

	hits, outcome, detail := xmlrpcMulticall(j, []Cred{{"admin", "bad"}, {"admin", "s3cret"}, {"admin", "bad"}})
	if outcome != outFail {
		t.Fatalf("outcome %v (%s), want outFail", outcome, detail)
	}
	if !hits[1].ok || hits[0].ok || hits[2].ok {
		t.Fatalf("wrong verdicts: %+v", hits)
	}
}
