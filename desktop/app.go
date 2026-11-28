package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/aiviarium/sparrow/desktop/localhub"
	"github.com/aiviarium/sparrow/go/cbor"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
)

// DesktopConfig is an optional JSON file (pointed to by SPARROW_DESKTOP_CONFIG
// or ~/.config/sparrow-desktop/config.json) that configures remote peer hubs,
// local modulesDir, and trusted root keys.
type DesktopConfig struct {
	DataDir    string                `json:"dataDir,omitempty"`
	ModulesDir string                `json:"modulesDir,omitempty"`
	Principal  string                `json:"principal,omitempty"`
	RootKeys   []string              `json:"rootKeys,omitempty"`
	Peers      []localhub.PeerConfig `json:"peers,omitempty"`
}

// App is the Wails v2 backend bound to the WebView frontend.
type App struct {
	ctx  context.Context
	hub  *localhub.Instance
	err  error
	log  *slog.Logger
	info localhub.ClientInfo
}

func NewApp() *App {
	return &App{log: slog.Default()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	cfg := loadDesktopConfig()

	inst, err := localhub.Start(ctx, localhub.Config{
		DataDir:    cfg.DataDir,
		ModulesDir: cfg.ModulesDir,
		Principal:  cfg.Principal,
		RootKeys:   cfg.RootKeys,
		Peers:      cfg.Peers,
		Logger:     a.log,
	})
	if err != nil {
		a.err = err
		a.log.Error("failed to start embedded local hub", "err", err)
		return
	}
	a.hub = inst
	a.info = inst.Info

	// Attach a built-in native local service ("desktop") demonstrating how local
	// Go services plug into the embedded hub with custom routing annotations.
	if err := a.attachBuiltInDesktopNode(ctx, inst); err != nil {
		a.log.Warn("failed to attach built-in desktop node", "err", err)
	}
	a.log.Info("sparrow desktop local hub ready",
		"web", inst.Info.BaseURL,
		"webtransport", inst.Info.WebTransport,
		"websocket", inst.Info.WebSocket,
	)
}

func (a *App) shutdown(ctx context.Context) {
	if a.hub != nil {
		a.hub.Close()
	}
}

// HubConfig returns the embedded local hub connection info (baseUrl, per-launch
// bearer token, endpoints, certHash, rootKeys) to the Wails WebView frontend.
func (a *App) HubConfig() localhub.ClientInfo {
	return a.info
}

func (a *App) attachBuiltInDesktopNode(ctx context.Context, inst *localhub.Instance) error {
	fb := nd.NewFacet("desktop", "1.0.0")
	svc := fb.Service("Desktop")
	svc.Method("info", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		b, _ := json.Marshal(map[string]any{
			"os":           runtime.GOOS,
			"arch":         runtime.GOARCH,
			"webtransport": inst.Info.WebTransport,
			"websocket":    inst.Info.WebSocket,
		})
		return string(b), nil
	}, nd.Idempotent())
	f := fb.MustBuild()
	f.Def.Annotations["app.locality"] = cbor.AppendText(nil, "local")
	_, err := inst.AttachLocalNode(ctx, "desktop", f)
	return err
}

func loadDesktopConfig() DesktopConfig {
	path := os.Getenv("SPARROW_DESKTOP_CONFIG")
	if path == "" {
		if dir, err := os.UserConfigDir(); err == nil {
			path = filepath.Join(dir, "sparrow-desktop", "config.json")
		}
	}
	if path == "" {
		return DesktopConfig{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return DesktopConfig{}
	}
	var cfg DesktopConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		slog.Warn("ignoring malformed desktop config", "path", path, "err", err)
		return DesktopConfig{}
	}
	return cfg
}
