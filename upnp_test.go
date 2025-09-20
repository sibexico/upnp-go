package upnp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Simulating a UPnP-enabled gateway.
type mockGateway struct {
	server          *httptest.Server
	lastAction      string
	lastRequestBody string
	responses       map[string]string
}

// Starting the mock server
func newMockGateway() *mockGateway {
	gw := &mockGateway{
		responses: make(map[string]string),
	}
	gw.server = httptest.NewServer(http.HandlerFunc(gw.handler))

	// Default responses
	gw.responses["GetExternalIPAddress"] = `
		<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
			<s:Body>
				<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
					<NewExternalIPAddress>123.123.123.123</NewExternalIPAddress>
				</u:GetExternalIPAddressResponse>
			</s:Body>
		</s:Envelope>
	`
	gw.responses["AddPortMapping"] = `
		<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
			<s:Body>
				<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse>
			</s:Body>
		</s:Envelope>
	`
	gw.responses["DeletePortMapping"] = `
		<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
			<s:Body>
				<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:DeletePortMappingResponse>
			</s:Body>
		</s:Envelope>
	`
	gw.responses["GetSpecificPortMappingEntry"] = `
		<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
			<s:Body>
				<u:GetSpecificPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
					<NewInternalPort>8080</NewInternalPort>
					<NewInternalClient>192.168.1.100</NewInternalClient>
					<NewEnabled>1</NewEnabled>
					<NewPortMappingDescription>Test Mapping</NewPortMappingDescription>
					<NewLeaseDuration>0</NewLeaseDuration>
				</u:GetSpecificPortMappingEntryResponse>
			</s:Body>
		</s:Envelope>
	`
	gw.responses["GetSpecificPortMappingEntry-NotFound"] = `
		<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
			<s:Body>
				<s:Fault>
					<faultcode>s:Client</faultcode>
					<faultstring>UPnPError</faultstring>
					<detail>
						<UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
							<errorCode>714</errorCode>
							<errorDescription>NoSuchEntryInArray</errorDescription>
						</UPnPError>
					</detail>
				</s:Fault>
			</s:Body>
		</s:Envelope>
	`

	return gw
}

func (gw *mockGateway) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/gatedesc.xml" {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `
			<root xmlns="urn:schemas-upnp-org:device-1-0">
				<device>
					<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
					<serviceList>
						<service>
							<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
							<controlURL>/ctl</controlURL>
						</service>
					</serviceList>
				</device>
			</root>
		`)
		return
	}

	if r.URL.Path == "/ctl" {
		soapAction := r.Header.Get("SOAPAction")
		actionParts := strings.Split(soapAction, "#")
		if len(actionParts) < 2 {
			http.Error(w, "Malformed SOAPAction", http.StatusBadRequest)
			return
		}
		action := strings.Trim(actionParts[1], `"`)
		gw.lastAction = action

		bodyBytes, _ := io.ReadAll(r.Body)
		gw.lastRequestBody = string(bodyBytes)

		response, ok := gw.responses[action]
		if !ok {
			http.Error(w, "SOAP Action not implemented in mock", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, response)
		return
	}

	http.NotFound(w, r)
}

func (gw *mockGateway) Close() {
	gw.server.Close()
}

func (gw *mockGateway) getIGDClient() (*IGD, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	return LoadCtx(ctx, gw.server.URL+"/gatedesc.xml")
}

// Testing if we can correctly fetch the device description
func TestLoad(t *testing.T) {
	gw := newMockGateway()
	defer gw.Close()

	igd, err := gw.getIGDClient()
	if err != nil {
		t.Fatalf("LoadCtx failed: %v", err)
	}

	if igd.device == nil {
		t.Fatal("IGD device is nil after load")
	}
	expectedControlURL := gw.server.URL + "/ctl"
	if igd.device.ControlURL != expectedControlURL {
		t.Errorf("Expected control URL %s, got %s", expectedControlURL, igd.device.ControlURL)
	}
}

// Verifying the GetExternalIPAddress, change expected IP
func TestExternalIP(t *testing.T) {
	gw := newMockGateway()
	defer gw.Close()

	igd, err := gw.getIGDClient()
	if err != nil {
		t.Fatalf("Failed to create IGD client: %v", err)
	}

	ip, err := igd.ExternalIP()
	if err != nil {
		t.Fatalf("ExternalIP failed: %v", err)
	}

	if gw.lastAction != "GetExternalIPAddress" {
		t.Errorf("Expected SOAP action 'GetExternalIPAddress', got '%s'", gw.lastAction)
	}

	expectedIP := "123.123.123.123"
	if ip != expectedIP {
		t.Errorf("Expected IP %s, got %s", expectedIP, ip)
	}
}

// Verifying the AddPortMapping
func TestForward(t *testing.T) {
	gw := newMockGateway()
	defer gw.Close()

	igd, err := gw.getIGDClient()
	if err != nil {
		t.Fatalf("Failed to create IGD client: %v", err)
	}

	igd.internalIP = "192.168.1.100"

	err = igd.Forward(8080, "Test Server")
	if err != nil {
		t.Fatalf("Forward failed: %v", err)
	}

	if gw.lastAction != "AddPortMapping" {
		t.Errorf("Expected SOAP action 'AddPortMapping', got '%s'", gw.lastAction)
	}

	if !strings.Contains(gw.lastRequestBody, "<NewExternalPort>8080</NewExternalPort>") {
		t.Error("Request body did not contain correct external port")
	}
	if !strings.Contains(gw.lastRequestBody, "<NewInternalClient>192.168.1.100</NewInternalClient>") {
		t.Error("Request body did not contain correct internal client IP")
	}
	if !strings.Contains(gw.lastRequestBody, "<NewProtocol>UDP</NewProtocol>") {
		t.Error("Request body did not contain correct protocol for the second forward call")
	}
}

// Verifying the the DeletePortMapping
func TestClear(t *testing.T) {
	gw := newMockGateway()
	defer gw.Close()

	igd, err := gw.getIGDClient()
	if err != nil {
		t.Fatalf("Failed to create IGD client: %v", err)
	}

	err = igd.Clear(8080)
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	if gw.lastAction != "DeletePortMapping" {
		t.Errorf("Expected SOAP action 'DeletePortMapping', got '%s'", gw.lastAction)
	}

	if !strings.Contains(gw.lastRequestBody, "<NewExternalPort>8080</NewExternalPort>") {
		t.Error("Request body did not contain correct external port")
	}
	if !strings.Contains(gw.lastRequestBody, "<NewProtocol>UDP</NewProtocol>") {
		t.Error("Request body did not contain correct protocol for the second clear call")
	}
}

// Verifying the parsing a successful mapping entry response
func TestGetPortMapping(t *testing.T) {
	gw := newMockGateway()
	defer gw.Close()

	igd, err := gw.getIGDClient()
	if err != nil {
		t.Fatalf("Failed to create IGD client: %v", err)
	}

	mapping, err := igd.GetPortMapping(9090, ProtocolTCP)
	if err != nil {
		t.Fatalf("GetPortMapping failed: %v", err)
	}

	if gw.lastAction != "GetSpecificPortMappingEntry" {
		t.Errorf("Expected SOAP action 'GetSpecificPortMappingEntry', got '%s'", gw.lastAction)
	}

	if mapping.InternalPort != 8080 {
		t.Errorf("Expected internal port 8080, got %d", mapping.InternalPort)
	}
	if mapping.InternalIP != "192.168.1.100" {
		t.Errorf("Expected internal IP '192.168.1.100', got '%s'", mapping.InternalIP)
	}
	if !mapping.Enabled {
		t.Error("Expected mapping to be enabled")
	}
}

// Verifying the handling of a "NoSuchEntryInArray" error
func TestGetPortMappingNotFound(t *testing.T) {
	gw := newMockGateway()
	defer gw.Close()

	gw.responses["GetSpecificPortMappingEntry"] = gw.responses["GetSpecificPortMappingEntry-NotFound"]

	igd, err := gw.getIGDClient()
	if err != nil {
		t.Fatalf("Failed to create IGD client: %v", err)
	}

	_, err = igd.GetPortMapping(9090, ProtocolTCP)
	if !errors.Is(err, ErrPortNotForwarded) {
		t.Fatalf("Expected ErrPortNotForwarded, got: %v", err)
	}
}
