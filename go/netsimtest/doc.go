// Package netsimtest runs the hub, clients and a node over real WebTransport
// and WebSocket connections through the bad networks of internal/netsim:
// packet loss, latency, reordering, duplication, dead links, NAT rebinding,
// tiny TCP segments, stalls and connection resets. Tests only.
package netsimtest
