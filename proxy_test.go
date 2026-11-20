package mssql

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// unknownFeatureExt is a FeatureExt entry the proxy does not track.
type unknownFeatureExt struct {
	id   byte
	data []byte
}

func (f *unknownFeatureExt) featureID() byte { return f.id }
func (f *unknownFeatureExt) toBytes() []byte { return f.data }

// Clients advertise features the proxy does not know about (e.g. JSONSUPPORT
// 0x0D from Microsoft.Data.SqlClient 6+). Those must be skipped, not rejected.
func TestReadLoginIgnoresUnknownFeatureExt(t *testing.T) {
	sent := login{
		TDSVersion: verTDS74,
		PacketSize: 4096,
		HostName:   "client",
		UserName:   "user",
		Password:   "pass",
		AppName:    "app",
		Database:   "db",
	}
	for _, f := range []featureExt{
		&featureExtUTF8Support{},
		&unknownFeatureExt{id: featExtAZURESQLSUPPORT, data: []byte{0x01}}, // 0x08
		&unknownFeatureExt{id: 0x0D, data: []byte{0x01}},                   // JSONSUPPORT
		&unknownFeatureExt{id: 0x0E, data: []byte{0x01}},                   // VECTORSUPPORT
		&unknownFeatureExt{id: featExtCOLUMNENCRYPTION},                    // known ID, empty data
	} {
		if err := sent.FeatureExt.Add(f); err != nil {
			t.Fatal(err)
		}
	}

	transport := closableBuffer{bytes.NewBuffer(nil)}
	if err := sendLogin(newTdsBuffer(4096, transport), &sent); err != nil {
		t.Fatalf("sendLogin: %v", err)
	}

	s := &Server{logger: zap.NewNop()}
	got, err := s.readLogin(newTdsBuffer(4096, transport))
	if err != nil {
		t.Fatalf("readLogin: %v", err)
	}

	if got.UserName != sent.UserName || got.Database != sent.Database {
		t.Errorf("login fields not parsed: got user=%q db=%q", got.UserName, got.Database)
	}
	if len(got.FeatureExt.features) != 1 {
		t.Errorf("expected only UTF8SUPPORT to be tracked, got %v", got.FeatureExt.features)
	}
	if _, ok := got.FeatureExt.features[featExtUTF8SUPPORT]; !ok {
		t.Errorf("UTF8SUPPORT missing from parsed features: %v", got.FeatureExt.features)
	}
}

// FEDAUTH carries credentials the proxy cannot validate, so it stays rejected.
func TestReadLoginRejectsFedAuth(t *testing.T) {
	sent := login{TDSVersion: verTDS74, PacketSize: 4096, UserName: "user", Database: "db"}
	if err := sent.FeatureExt.Add(&featureExtFedAuth{FedAuthLibrary: FedAuthLibrarySecurityToken, FedAuthToken: "tok"}); err != nil {
		t.Fatal(err)
	}

	transport := closableBuffer{bytes.NewBuffer(nil)}
	if err := sendLogin(newTdsBuffer(4096, transport), &sent); err != nil {
		t.Fatalf("sendLogin: %v", err)
	}

	s := &Server{logger: zap.NewNop()}
	_, err := s.readLogin(newTdsBuffer(4096, transport))
	if err == nil || !strings.Contains(err.Error(), "federated authentication") {
		t.Fatalf("expected federated authentication error, got %v", err)
	}
	if strings.Contains(err.Error(), "tok") {
		t.Errorf("error must not include the token: %v", err)
	}
}
