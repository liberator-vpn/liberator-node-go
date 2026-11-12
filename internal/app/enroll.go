package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
)

func (app *App) identityPath() string {
	if app.cfg.API.IdentityFile != "" {
		return app.cfg.API.IdentityFile
	}
	dir := app.cfg.API.StateDir
	if dir == "" {
		dir = "./state"
	}
	return filepath.Join(dir, "node-identity.json")
}

// ensureIdentity загружает сохранённую identity или enroll'ит ноду.
// Повторный enroll возможен по reusable-токену: API обновит существующую
// ноду по стабильному имени и выдаст новый secret.
func (app *App) ensureIdentity(ctx context.Context) (*apiclient.Identity, error) {
	path := app.identityPath()
	id, err := apiclient.LoadIdentity(path)
	if err != nil {
		return nil, err
	}
	if id != nil {
		if err := app.verifyIdentity(ctx, id); err == nil {
			log.Printf("node identity loaded: node_id=%s path=%s", id.NodeID, path)
			return id, nil
		} else if app.cfg.API.EnrollmentToken == "" {
			return nil, fmt.Errorf("stored node identity is rejected by API and api.enrollment_token is empty: %w", err)
		} else {
			log.Printf("stored node identity is rejected by API, re-enrolling: %v", err)
		}
	} else if app.cfg.API.IdentityFile != "" {
		return nil, fmt.Errorf("api.identity_file %s not found or incomplete; refusing to write enrollment identity into a read-only file", path)
	}

	if app.cfg.API.EnrollmentToken == "" {
		return nil, fmt.Errorf("no node identity at %s and api.enrollment_token is empty; create an enrollment token in the API and put it into config/env", path)
	}
	client := apiclient.New(app.cfg.API.BaseURL, "")
	if client == nil {
		return nil, fmt.Errorf("api.base_url is required for enrollment")
	}

	name := app.cfg.API.NodeName
	if name == "" {
		name = nodeIdentity()
	}
	labels := make(map[string]any, len(app.cfg.API.Labels))
	for k, v := range app.cfg.API.Labels {
		labels[k] = v
	}
	res, err := client.Enroll(ctx, apiclient.EnrollRequest{
		Token:          app.cfg.API.EnrollmentToken,
		Name:           name,
		Hostname:       nodeIdentity(),
		PublicEndpoint: app.cfg.API.PublicEndpoint,
		MeshEndpoint:   app.cfg.API.MeshEndpoint,
		RegionCode:     app.cfg.API.RegionCode,
		Zone:           app.cfg.API.Zone,
		Provider:       app.cfg.API.Provider,
		AgentVersion:   app.cfg.API.AgentVersion,
		Labels:         labels,
		Capabilities:   buildCapabilities(app.cfg),
		Protocols:      buildProtocols(app.cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("api enroll: %w", err)
	}
	id = &apiclient.Identity{
		NodeID: res.NodeID, Secret: res.Secret,
		GatewayAddr: res.GatewayAddr, GlobalCIDR: res.GlobalCIDR,
	}
	if err := apiclient.SaveIdentity(path, id); err != nil {
		return nil, fmt.Errorf("save node identity: %w", err)
	}
	log.Printf("node enrolled: node_id=%s gateway=%s identity=%s", id.NodeID, id.GatewayAddr, path)
	return id, nil
}

// verifyIdentity проверяет, что API принимает сохранённый node_id+secret.
// Сетевые ошибки не считаются протухшей identity: нода должна уметь
// пережить недоступность control-plane при старте.
func (app *App) verifyIdentity(ctx context.Context, id *apiclient.Identity) error {
	client := apiclient.New(app.cfg.API.BaseURL, id.Secret)
	if client == nil {
		return nil
	}
	_, err := client.Whoami(ctx, id.NodeID)
	if err == nil {
		return nil
	}
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
		return err
	}
	log.Printf("identity check failed, keeping stored identity: %v", err)
	return nil
}
