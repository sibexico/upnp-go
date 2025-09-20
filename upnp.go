package upnp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNoGateway is returned when no UPnP-enabled gateway device can be found on the network.
	ErrNoGateway = errors.New("no UPnP-enabled gateway found")
	// ErrPortNotForwarded is returned when a specific port mapping is requested but does not exist.
	ErrPortNotForwarded = errors.New("port is not forwarded")
	// ErrInvalidPort is returned for port numbers that are out of the valid range (i.e., 0).
	ErrInvalidPort = errors.New("invalid port number")
	// ErrNoInternalIP is returned when the local IP address of the client cannot be determined.
	ErrNoInternalIP = errors.New("could not determine internal IP")
	// ErrSOAPAction is returned when a SOAP request to the gateway fails.
	ErrSOAPAction = errors.New("SOAP action failed")
)

// Protocol defines the network protocol for port mapping, either TCP or UDP.
type Protocol string

const (
	// ProtocolTCP represents the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP represents the UDP protocol.
	ProtocolUDP Protocol = "UDP"
)

const (
	ssdpAddr                      = "239.255.255.250:1900"
	httpTimeout                   = 8 * time.Second
	wanIPConnectionServicePrefix  = "urn:schemas-upnp-org:service:WANIPConnection:"
	wanPPPConnectionServicePrefix = "urn:schemas-upnp-org:service:WANPPPConnection:"
)

// PortMapping holds the details of a port forwarding entry on an Internet Gateway Device.
type PortMapping struct {
	// ExternalPort is the port number on the gateway's external interface.
	ExternalPort uint16
	// InternalPort is the port number on the internal client.
	InternalPort uint16
	// InternalIP is the IP address of the internal client.
	InternalIP string
	// Protocol is the network protocol (TCP or UDP) for the mapping.
	Protocol Protocol
	// Enabled indicates whether the port mapping is active.
	Enabled bool
	// Description is a user-defined description for the port mapping.
	Description string
	// LeaseDuration is the duration of the port mapping in seconds. A value of 0 means an infinite lease.
	LeaseDuration uint32
}

// Device represents a discovered UPnP device on the network.
// It contains the necessary information to interact with its services.
type Device struct {
	// Location is the URL to the device's XML description file.
	Location string
	// ServiceType is the URN of the WAN service (e.g., WANIPConnection:1).
	ServiceType string
	// ControlURL is the URL for sending SOAP requests to the service.
	ControlURL string
	// USN is the Unique Service Name of the device.
	USN string
}

// IGD represents an Internet Gateway Device that supports UPnP.
// It provides methods to interact with the device, such as managing port mappings and querying its status.
type IGD struct {
	device       *Device
	httpClient   *http.Client
	internalIP   string
	internalIPMu sync.RWMutex
}

// Structures for parsing the description XML
type root struct {
	XMLName xml.Name `xml:"root"`
	Device  device   `xml:"device"`
}

type device struct {
	DeviceType  string    `xml:"deviceType"`
	UDN         string    `xml:"UDN"`
	ServiceList []service `xml:"serviceList>service"`
	DeviceList  []device  `xml:"deviceList>device"`
}

type service struct {
	ServiceType string `xml:"serviceType"`
	ServiceId   string `xml:"serviceId"`
	ControlURL  string `xml:"controlURL"`
}

type soapRequestEnvelope struct {
	XMLName  xml.Name        `xml:"soap:Envelope"`
	XMLNS    string          `xml:"xmlns:soap,attr"`
	Encoding string          `xml:"soap:encodingStyle,attr"`
	Body     soapRequestBody `xml:"soap:Body"`
}

type soapRequestBody struct {
	Action interface{} `xml:",any"`
}

type soapResponseEnvelope struct {
	XMLName xml.Name         `xml:"Envelope"`
	Body    soapResponseBody `xml:"Body"`
}

type soapResponseBody struct {
	Action interface{} `xml:",any"`
}

type soapFault struct {
	XMLName xml.Name   `xml:"Fault"`
	Code    string     `xml:"faultcode"`
	String  string     `xml:"faultstring"`
	Detail  soapDetail `xml:"detail"`
}

type soapDetail struct {
	UPnPError upnpError `xml:"UPnPError"`
}

type upnpError struct {
	ErrorCode        int    `xml:"errorCode"`
	ErrorDescription string `xml:"errorDescription"`
}

type getExternalIPRequest struct {
	XMLName xml.Name `xml:"u:GetExternalIPAddress"`
	XMLNS   string   `xml:"xmlns:u,attr"`
}

type getExternalIPResponse struct {
	XMLName    xml.Name `xml:"GetExternalIPAddressResponse"`
	ExternalIP string   `xml:"NewExternalIPAddress"`
}

type addPortMappingRequest struct {
	XMLName                xml.Name `xml:"u:AddPortMapping"`
	XMLNS                  string   `xml:"xmlns:u,attr"`
	RemoteHost             string   `xml:"NewRemoteHost"`
	ExternalPort           uint16   `xml:"NewExternalPort"`
	Protocol               string   `xml:"NewProtocol"`
	InternalPort           uint16   `xml:"NewInternalPort"`
	InternalClient         string   `xml:"NewInternalClient"`
	Enabled                string   `xml:"NewEnabled"`
	PortMappingDescription string   `xml:"NewPortMappingDescription"`
	LeaseDuration          uint32   `xml:"NewLeaseDuration"`
}

type deletePortMappingRequest struct {
	XMLName      xml.Name `xml:"u:DeletePortMapping"`
	XMLNS        string   `xml:"xmlns:u,attr"`
	RemoteHost   string   `xml:"NewRemoteHost"`
	ExternalPort uint16   `xml:"NewExternalPort"`
	Protocol     string   `xml:"NewProtocol"`
}

type getSpecificPortMappingRequest struct {
	XMLName      xml.Name `xml:"u:GetSpecificPortMappingEntry"`
	XMLNS        string   `xml:"xmlns:u,attr"`
	RemoteHost   string   `xml:"NewRemoteHost"`
	ExternalPort uint16   `xml:"NewExternalPort"`
	Protocol     string   `xml:"NewProtocol"`
}

type getSpecificPortMappingResponse struct {
	XMLName                xml.Name `xml:"GetSpecificPortMappingEntryResponse"`
	InternalPort           uint16   `xml:"NewInternalPort"`
	InternalClient         string   `xml:"NewInternalClient"`
	Enabled                string   `xml:"NewEnabled"`
	PortMappingDescription string   `xml:"NewPortMappingDescription"`
	LeaseDuration          uint32   `xml:"NewLeaseDuration"`
}

// ExternalIP retrieves the external IP address of the gateway.
func (d *IGD) ExternalIP() (string, error) {
	return d.ExternalIPCtx(context.Background())
}

// ExternalIPCtx retrieves the external IP address of the gateway using a context.
func (d *IGD) ExternalIPCtx(ctx context.Context) (string, error) {
	if d.device == nil {
		return "", errors.New("IGD device is nil")
	}
	req := getExternalIPRequest{
		XMLNS: d.device.ServiceType,
	}
	var resp getExternalIPResponse
	err := d.performSOAPActionWithContext(ctx, "GetExternalIPAddress", req, &resp)
	if err != nil {
		return "", fmt.Errorf("failed to get external IP: %w", err)
	}
	return resp.ExternalIP, nil
}

// IsForwarded checks if a specific port is forwarded for the given protocol.
// It returns true if an enabled mapping exists for the port and protocol.
func (d *IGD) IsForwarded(port uint16, protocol Protocol) (bool, error) {
	if err := validatePort(port); err != nil {
		return false, err
	}
	mapping, err := d.GetPortMapping(port, protocol)
	if err != nil {
		if errors.Is(err, ErrPortNotForwarded) {
			return false, nil
		}
		return false, err
	}
	return mapping.Enabled, nil
}

// IsForwardedTCP is a convenience function to check if a TCP port is forwarded.
func (d *IGD) IsForwardedTCP(port uint16) (bool, error) {
	return d.IsForwarded(port, ProtocolTCP)
}

// IsForwardedUDP is a convenience function to check if a UDP port is forwarded.
func (d *IGD) IsForwardedUDP(port uint16) (bool, error) {
	return d.IsForwarded(port, ProtocolUDP)
}

// GetPortMapping retrieves the details of a specific port mapping.
// If the mapping does not exist, it returns ErrPortNotForwarded.
func (d *IGD) GetPortMapping(port uint16, protocol Protocol) (*PortMapping, error) {
	if err := validatePort(port); err != nil {
		return nil, err
	}
	req := getSpecificPortMappingRequest{
		XMLNS:        d.device.ServiceType,
		RemoteHost:   "",
		ExternalPort: port,
		Protocol:     string(protocol),
	}
	var resp getSpecificPortMappingResponse
	err := d.performSOAPAction("GetSpecificPortMappingEntry", req, &resp)
	if err != nil {
		if strings.Contains(err.Error(), "714") || strings.Contains(err.Error(), "NoSuchEntryInArray") {
			return nil, ErrPortNotForwarded
		}
		return nil, fmt.Errorf("failed to get port mapping: %w", err)
	}
	return &PortMapping{
		ExternalPort:  port,
		InternalPort:  resp.InternalPort,
		InternalIP:    resp.InternalClient,
		Protocol:      protocol,
		Enabled:       resp.Enabled == "1",
		Description:   resp.PortMappingDescription,
		LeaseDuration: resp.LeaseDuration,
	}, nil
}

// Forward creates port mappings for both TCP and UDP protocols for the specified external port.
// The internal port will be the same as the external port.
// If forwarding the UDP port fails, it attempts to clear the TCP port mapping.
func (d *IGD) Forward(port uint16, desc string) error {
	if err := validatePort(port); err != nil {
		return err
	}
	if err := d.ForwardTCP(port, desc); err != nil {
		return fmt.Errorf("failed to forward TCP port %d: %w", port, err)
	}
	if err := d.ForwardUDP(port, desc); err != nil {
		d.ClearTCP(port)
		return fmt.Errorf("failed to forward UDP port %d: %w", port, err)
	}
	return nil
}

// ForwardProtocol creates a port mapping for the specified protocol.
// It maps the external port to the same internal port on the client's internal IP address.
func (d *IGD) ForwardProtocol(port uint16, protocol Protocol, desc string) error {
	if err := validatePort(port); err != nil {
		return err
	}
	ip, err := d.getInternalIP()
	if err != nil {
		return err
	}
	req := addPortMappingRequest{
		XMLNS:                  d.device.ServiceType,
		RemoteHost:             "",
		ExternalPort:           port,
		Protocol:               string(protocol),
		InternalPort:           port,
		InternalClient:         ip,
		Enabled:                "1",
		PortMappingDescription: desc,
		LeaseDuration:          0, // Infinite lease
	}
	err = d.performSOAPAction("AddPortMapping", req, nil)
	if err != nil {
		return fmt.Errorf("failed to add port mapping for %s port %d: %w", protocol, port, err)
	}
	return nil
}

// ForwardTCP is a convenience function to create a TCP port mapping.
func (d *IGD) ForwardTCP(port uint16, desc string) error {
	return d.ForwardProtocol(port, ProtocolTCP, desc)
}

// ForwardUDP is a convenience function to create a UDP port mapping.
func (d *IGD) ForwardUDP(port uint16, desc string) error {
	return d.ForwardProtocol(port, ProtocolUDP, desc)
}

// Clear removes port mappings for both TCP and UDP protocols for the specified external port.
// It returns an error only if both clear operations fail.
func (d *IGD) Clear(port uint16) error {
	if err := validatePort(port); err != nil {
		return err
	}
	tcpErr := d.ClearTCP(port)
	udpErr := d.ClearUDP(port)
	if tcpErr != nil && udpErr != nil {
		return fmt.Errorf("failed to clear port %d: TCP error: %v, UDP error: %v", port, tcpErr, udpErr)
	}
	return nil
}

// ClearProtocol removes a port mapping for the specified protocol and external port.
func (d *IGD) ClearProtocol(port uint16, protocol Protocol) error {
	if err := validatePort(port); err != nil {
		return err
	}
	req := deletePortMappingRequest{
		XMLNS:        d.device.ServiceType,
		RemoteHost:   "",
		ExternalPort: port,
		Protocol:     string(protocol),
	}
	err := d.performSOAPAction("DeletePortMapping", req, nil)
	if err != nil {
		return fmt.Errorf("failed to delete %s port mapping for port %d: %w", protocol, port, err)
	}
	return nil
}

// ClearTCP is a convenience function to remove a TCP port mapping.
func (d *IGD) ClearTCP(port uint16) error {
	return d.ClearProtocol(port, ProtocolTCP)
}

// ClearUDP is a convenience function to remove a UDP port mapping.
func (d *IGD) ClearUDP(port uint16) error {
	return d.ClearProtocol(port, ProtocolUDP)
}

// Location returns the URL of the gateway's device description XML file.
func (d *IGD) Location() string {
	if d.device == nil {
		return ""
	}
	return d.device.Location
}

func (d *IGD) performSOAPAction(action string, request, response interface{}) error {
	return d.performSOAPActionWithContext(context.Background(), action, request, response)
}

func (d *IGD) performSOAPActionWithContext(ctx context.Context, action string, request, response interface{}) error {
	fullRequest := soapRequestEnvelope{
		XMLNS:    "http://schemas.xmlsoap.org/soap/envelope/",
		Encoding: "http://schemas.xmlsoap.org/soap/encoding/",
		Body:     soapRequestBody{Action: request},
	}
	payload := []byte(xml.Header)
	marshaled, err := xml.Marshal(fullRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal SOAP request: %w", err)
	}
	payload = append(payload, marshaled...)
	req, err := http.NewRequestWithContext(ctx, "POST", d.device.ControlURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, d.device.ServiceType, action))
	req.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	req.Header.Set("Connection", "Close")
	req.Header.Set("User-Agent", "UPnP/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SOAP request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d: %s", ErrSOAPAction, resp.StatusCode, string(respBody))
	}
	if response != nil {
		respEnvelope := soapResponseEnvelope{Body: soapResponseBody{Action: response}}
		err = xml.Unmarshal(respBody, &respEnvelope)
		if err != nil {
			var fault soapFault
			// Unmarshal as a wrong response
			faultEnvelope := soapResponseEnvelope{Body: soapResponseBody{Action: &fault}}
			if xml.Unmarshal(respBody, &faultEnvelope) == nil && (fault.Code != "" || fault.Detail.UPnPError.ErrorCode != 0) {
				if fault.Detail.UPnPError.ErrorCode != 0 {
					return fmt.Errorf("%w: UPnP Error %d: %s", ErrSOAPAction, fault.Detail.UPnPError.ErrorCode, fault.Detail.UPnPError.ErrorDescription)
				}
				return fmt.Errorf("%w: %s - %s", ErrSOAPAction, fault.Code, fault.String)
			}
			return fmt.Errorf("failed to parse SOAP response: %w", err)
		}
	}
	return nil
}

func (d *IGD) getInternalIP() (string, error) {
	d.internalIPMu.RLock()
	if d.internalIP != "" {
		ip := d.internalIP
		d.internalIPMu.RUnlock()
		return ip, nil
	}
	d.internalIPMu.RUnlock()
	d.internalIPMu.Lock()
	defer d.internalIPMu.Unlock()
	if d.internalIP != "" {
		return d.internalIP, nil
	}
	deviceURL, err := url.Parse(d.device.Location)
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse device location: %v", ErrNoInternalIP, err)
	}
	host, _, _ := net.SplitHostPort(deviceURL.Host)
	if host == "" {
		host = deviceURL.Host
	}
	devIP := net.ParseIP(host)
	if devIP == nil {
		return "", fmt.Errorf("%w: could not parse router IP from %s", ErrNoInternalIP, host)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("%w: failed to get network interfaces: %v", ErrNoInternalIP, err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.Contains(devIP) && !ipNet.IP.IsLoopback() {
				d.internalIP = ipNet.IP.String()
				return d.internalIP, nil
			}
		}
	}
	return "", ErrNoInternalIP
}

func validatePort(port uint16) error {
	if port == 0 {
		return fmt.Errorf("%w: port cannot be 0", ErrInvalidPort)
	}
	return nil
}

// Discover searches the local network for a UPnP-enabled Internet Gateway Device.
// It returns an IGD instance if a compatible device is found.
// If no device is found, it returns ErrNoGateway. The discovery process times out after 10 seconds.
func Discover() (*IGD, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Increased timeout for brute force
	defer cancel()
	return DiscoverCtx(ctx)
}

// DiscoverCtx searches the local network for a UPnP-enabled Internet Gateway Device using a context.
// It returns an IGD instance if a compatible device is found.
// If no device is found or the context is canceled, it returns an error.
func DiscoverCtx(ctx context.Context) (*IGD, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	var wg sync.WaitGroup
	deviceCh := make(chan *Device)
	discovered := &sync.Map{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		wg.Add(1)
		go discoverOnInterface(ctx, &wg, iface, deviceCh, discovered)
	}
	go func() {
		wg.Wait()
		close(deviceCh)
	}()
	for device := range deviceCh {
		igd, err := LoadCtx(ctx, device.Location)
		if err == nil {
			return igd, nil
		}
		log.Printf("DEBUG: Failed to validate device at %s: %v", device.Location, err)
	}
	return nil, ErrNoGateway
}

func discoverOnInterface(ctx context.Context, wg *sync.WaitGroup, iface net.Interface, deviceCh chan<- *Device, discovered *sync.Map) {
	defer wg.Done()

	addrs, err := iface.Addrs()
	if err != nil {
		return
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}

		ip := ipNet.IP

		// Separate search for each IP on the interface
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			mcastAddr, err := net.ResolveUDPAddr("udp4", ssdpAddr)
			if err != nil {
				return
			}

			// Create a single socket bound to this IP
			laddr := &net.UDPAddr{IP: ip, Port: 0}
			conn, err := net.ListenUDP("udp4", laddr)
			if err != nil {
				return
			}
			defer conn.Close()

			deadline, _ := ctx.Deadline()
			conn.SetDeadline(deadline)

			searchTargets := []string{
				"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
				"ssdp:rootdevice",
				"upnp:rootdevice",
			}
			requestBytes := new(bytes.Buffer)
			for _, target := range searchTargets {
				requestBytes.Reset()
				requestBytes.WriteString("M-SEARCH * HTTP/1.1\r\n")
				requestBytes.WriteString(fmt.Sprintf("HOST: %s\r\n", ssdpAddr))
				requestBytes.WriteString("MAN: \"ssdp:discover\"\r\n")
				requestBytes.WriteString("MX: 2\r\n")
				requestBytes.WriteString(fmt.Sprintf("ST: %s\r\n", target))
				requestBytes.WriteString("\r\n")
				_, err := conn.WriteToUDP(requestBytes.Bytes(), mcastAddr)
				if err != nil {
					continue
				}
			}

			respBuf := make([]byte, 2048)
			for {
				n, _, err := conn.ReadFromUDP(respBuf)
				if err != nil {
					// The way to exit the loop
					return
				}

				resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respBuf[:n])), nil)
				if err != nil {
					continue
				}
				resp.Body.Close()

				usn := resp.Header.Get("Usn")
				location := resp.Header.Get("Location")
				if usn == "" || location == "" {
					continue
				}

				if _, loaded := discovered.LoadOrStore(usn, true); !loaded {
					device := &Device{
						Location: location,
						USN:      usn,
					}
					select {
					case deviceCh <- device:
					case <-ctx.Done():
						return
					}
				}
			}
		}(ip)
	}
}

func findWANService(dev device, baseURL *url.URL) *Device {
	for _, svc := range dev.ServiceList {
		if strings.HasPrefix(svc.ServiceType, wanIPConnectionServicePrefix) || strings.HasPrefix(svc.ServiceType, wanPPPConnectionServicePrefix) {
			controlURL, err := url.Parse(svc.ControlURL)
			if err != nil {
				continue
			}
			return &Device{
				ServiceType: svc.ServiceType,
				ControlURL:  baseURL.ResolveReference(controlURL).String(),
				USN:         dev.UDN,
			}
		}
	}
	for _, nestedDev := range dev.DeviceList {
		if found := findWANService(nestedDev, baseURL); found != nil {
			return found
		}
	}
	return nil
}

func findWANServiceByBruteForce(ctx context.Context, dev device, baseURL *url.URL) *Device {
	for _, svc := range dev.ServiceList {
		controlURL, err := url.Parse(svc.ControlURL)
		if err != nil {
			continue
		}
		testDevice := &Device{
			ServiceType: svc.ServiceType,
			ControlURL:  baseURL.ResolveReference(controlURL).String(),
			USN:         dev.UDN,
		}
		tempIGD := &IGD{
			device:     testDevice,
			httpClient: &http.Client{Timeout: 2 * time.Second},
		}
		_, err = tempIGD.ExternalIPCtx(ctx)
		if err == nil {
			log.Printf("DEBUG: Brute-force success! Found active WAN service: %s", svc.ServiceType)
			return testDevice
		}
	}

	for _, nestedDev := range dev.DeviceList {
		if found := findWANServiceByBruteForce(ctx, nestedDev, baseURL); found != nil {
			return found
		}
	}
	return nil
}

func fetchDeviceDescription(ctx context.Context, location string) (*Device, error) {
	client := &http.Client{Timeout: httpTimeout}
	req, err := http.NewRequestWithContext(ctx, "GET", location, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "UPnP/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d when fetching device description", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var desc root
	err = xml.Unmarshal(body, &desc)
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(location)
	if err != nil {
		return nil, err
	}

	foundDevice := findWANService(desc.Device, baseURL)

	if foundDevice == nil {
		log.Println("DEBUG: Standard service search failed. Trying brute-force discovery...")
		foundDevice = findWANServiceByBruteForce(ctx, desc.Device, baseURL)
	}

	if foundDevice != nil {
		foundDevice.Location = location
		return foundDevice, nil
	}

	return nil, errors.New("no compatible WAN service found in device description")
}

// Load creates an IGD instance from a specific device description URL.
// This is useful if the location of the gateway is already known.
func Load(rawurl string) (*IGD, error) {
	return LoadCtx(context.Background(), rawurl)
}

// LoadCtx creates an IGD instance from a specific device description URL using a context.
func LoadCtx(ctx context.Context, rawurl string) (*IGD, error) {
	if rawurl == "" {
		return nil, errors.New("empty URL provided")
	}
	device, err := fetchDeviceDescription(ctx, rawurl)
	if err != nil {
		return nil, fmt.Errorf("%w at URL %s: %v", ErrNoGateway, rawurl, err)
	}
	igd := &IGD{
		device:     device,
		httpClient: &http.Client{Timeout: httpTimeout},
	}
	return igd, nil
}
