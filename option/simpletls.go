package option

type SimpleTLSInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users []SimpleTLSUser `json:"users,omitempty"`
}

type SimpleTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type SimpleTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Password string `json:"password"`
}
