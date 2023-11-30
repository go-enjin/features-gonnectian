// Copyright (c) 2022  The Go-Enjin Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gonnectian

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/urfave/cli/v2"
	"gorm.io/gorm"

	times "github.com/go-enjin/github-com-djherbis-times"

	gonnect "github.com/go-enjin/github-com-craftamap-atlas-gonnect"
	"github.com/go-enjin/github-com-craftamap-atlas-gonnect/middleware"
	"github.com/go-enjin/github-com-craftamap-atlas-gonnect/routes"
	"github.com/go-enjin/github-com-craftamap-atlas-gonnect/store"

	"github.com/go-enjin/be/pkg/feature/signaling"

	beContext "github.com/go-enjin/be/pkg/context"
	"github.com/go-enjin/be/pkg/feature"
	beForms "github.com/go-enjin/be/pkg/forms"
	"github.com/go-enjin/be/pkg/globals"
	"github.com/go-enjin/be/pkg/log"
	"github.com/go-enjin/be/pkg/net"
	"github.com/go-enjin/be/pkg/net/headers/policy/csp"
	"github.com/go-enjin/be/pkg/net/ip/ranges/atlassian"
	"github.com/go-enjin/be/pkg/net/serve"
	bePath "github.com/go-enjin/be/pkg/path"
	"github.com/go-enjin/be/pkg/slices"
	"github.com/go-enjin/be/types/page"
)

// TODO: implement a v2 of gonnectian as a feature filesystem

const (
	SignalRouteHandled signaling.Signal = "gonnectian-route-handled"
)

const Tag feature.Tag = "gonnectian"

var (
	_ Feature     = (*CFeature)(nil)
	_ MakeFeature = (*CFeature)(nil)
)

type Feature interface {
	feature.Feature
	feature.Processor
	feature.UseMiddleware
	feature.ApplyMiddleware
	feature.PageContextModifier
	feature.UserActionsProvider

	GetPluginInstallationURL() (url string)
	GetPluginDescriptor() (descriptor *Descriptor)
	FindTenantByUrl(url string) (tenant *store.Tenant)
}

type MakeFeature interface {
	Make() Feature

	SetGormDB(tag string) MakeFeature
	SetTableName(table string) MakeFeature

	EnableIpValidation(enabled bool) MakeFeature
	ProfileBaseUrl(baseUrl string) MakeFeature
	ProfileBaseRoute(mount string) MakeFeature
	ProfileSignedInstall(signedInstall bool) MakeFeature

	ConnectFromJSON(encoded []byte) MakeFeature
	ConnectInfo(name, key, description, baseUrl string) MakeFeature
	ConnectVendor(name, url string) MakeFeature
	ConnectScopes(scopes ...string) MakeFeature
	ConnectApiVersion(apiVersion int) MakeFeature
	ConnectLicensing(enable bool) MakeFeature

	ConnectEnabledHandler(handler http.Handler) MakeFeature
	ConnectDisabledHandler(handler http.Handler) MakeFeature

	AddGeneralPageFromString(key, path, name, iconUrl string, raw string) MakeFeature
	AddGeneralPageFromFile(key, path, name, iconUrl string, filePath string) MakeFeature
	AddGeneralPageProcessor(key, path, name, iconUrl string, processor feature.ReqProcessFn) MakeFeature

	AddDashboardItemFromString(key, name, thumbnailUrl, description, path, raw string) MakeFeature
	AddDashboardItemFromStringWithConfig(key, name, thumbnailUrl, description, path, raw, configPath, configRaw string) MakeFeature
	AddDashboardItemFromFile(key, name, thumbnailUrl, description, path, filePath string) MakeFeature
	AddDashboardItemFromFileWithConfig(key, name, thumbnailUrl, description, path, filePath, configPath, configFile string) MakeFeature
	AddDashboardItemProcessor(key, path, name, thumbnailUrl, description string, processor feature.ReqProcessFn) MakeFeature
	AddDashboardItemProcessorWithConfig(key, path, name, thumbnailUrl, description, configPath string, configProcessor, processor feature.ReqProcessFn) MakeFeature

	AddConnectModule(name string, module interface{}) MakeFeature
	AddRouteHandler(route string, handler http.Handler) MakeFeature
	AddRouteProcessor(route string, processor feature.ReqProcessFn) MakeFeature

	AddContentSecurityPolicyDirective(p csp.Directive) MakeFeature
}

type CFeature struct {
	feature.CFeature

	makeName       string
	makeTag        string
	makeEnv        string
	baseRoute      string
	profile        *gonnect.Profile
	descriptor     *Descriptor
	generalPages   GeneralPages
	dashboardItems DashboardItems

	validateIp bool
	ipRanges   []string
	handlers   map[string]http.Handler
	processors map[string]feature.ReqProcessFn

	connectEnabledHandler  http.Handler
	connectDisabledHandler http.Handler

	addon *gonnect.Addon

	dbTag   string
	dbTable string

	cspDirectives []csp.Directive
}

func New(name, tag, env string) MakeFeature {
	if name == "" || tag == "" || env == "" {
		log.FatalDF(1, "gonnectian feature requires non-empty name, tag and env arguments")
		return nil
	}
	f := new(CFeature)
	f.makeName = name
	f.makeTag = tag
	f.makeEnv = env
	f.Init(f)
	f.PackageTag = Tag
	f.FeatureTag = Tag
	return f
}

func (f *CFeature) Init(this interface{}) {
	f.CFeature.Init(this)
	f.dbTag = ""
	f.dbTable = ""
	f.profile = new(gonnect.Profile)
	f.descriptor = NewDescriptor()
	f.descriptor.APIMigrations.SignedInstall = true
	f.descriptor.Version = globals.Version
	f.generalPages = make(GeneralPages, 0)
	f.dashboardItems = make(DashboardItems, 0)
	f.handlers = make(map[string]http.Handler)
	f.processors = make(map[string]feature.ReqProcessFn)
}

func (f *CFeature) SetGormDB(tag string) MakeFeature {
	f.dbTag = tag
	return f
}

func (f *CFeature) SetTableName(table string) MakeFeature {
	f.dbTable = table
	return f
}

func (f *CFeature) EnableIpValidation(enabled bool) MakeFeature {
	f.validateIp = enabled
	return f
}

func (f *CFeature) ProfileBaseUrl(baseUrl string) MakeFeature {
	f.profile.BaseUrl = baseUrl
	return f
}

func (f *CFeature) ProfileBaseRoute(mount string) MakeFeature {
	f.baseRoute = mount
	return f
}

func (f *CFeature) ProfileSignedInstall(signedInstall bool) MakeFeature {
	f.profile.SignedInstall = signedInstall
	return f
}

func (f *CFeature) ConnectFromJSON(encoded []byte) MakeFeature {
	if v, err := NewDescriptorFromJSON(encoded); err != nil {
		log.FatalDF(1, "error decoding %v gonnectian json descriptor: %v", f.makeName, err)
	} else {
		f.descriptor = v
	}
	return f
}

func (f *CFeature) ConnectInfo(name, key, description, baseUrl string) MakeFeature {
	f.descriptor.Name = name
	f.descriptor.Key = key
	f.descriptor.Description = description
	f.descriptor.BaseURL = baseUrl
	f.descriptor.APIMigrations.SignedInstall = true
	return f
}

func (f *CFeature) ConnectVendor(name, url string) MakeFeature {
	f.descriptor.Vendor.Name = name
	f.descriptor.Vendor.URL = url
	return f
}

func (f *CFeature) ConnectScopes(scopes ...string) MakeFeature {
	for _, scope := range scopes {
		scope = strings.ToUpper(scope)
		if !slices.Present(scope, f.descriptor.Scopes...) {
			f.descriptor.Scopes = append(
				f.descriptor.Scopes,
				scope,
			)
		}
	}
	return f
}

func (f *CFeature) ConnectApiVersion(apiVersion int) MakeFeature {
	f.descriptor.ApiVersion = apiVersion
	return f
}

func (f *CFeature) ConnectLicensing(enable bool) MakeFeature {
	f.descriptor.Licensing = enable
	return f
}

func (f *CFeature) ConnectEnabledHandler(handler http.Handler) MakeFeature {
	f.connectEnabledHandler = handler
	return f
}

func (f *CFeature) ConnectDisabledHandler(handler http.Handler) MakeFeature {
	f.connectDisabledHandler = handler
	return f
}

func (f *CFeature) AddGeneralPageFromString(key, path, name, iconUrl string, raw string) MakeFeature {
	f.generalPages = append(
		f.generalPages,
		NewGeneralPage(key, path, name, iconUrl),
	)
	return f.AddRouteProcessor(path, f.makeProcessorFromPageString(path, raw))
}

func (f *CFeature) AddGeneralPageFromFile(key, path, name, iconUrl string, filePath string) MakeFeature {
	f.generalPages = append(
		f.generalPages,
		NewGeneralPage(key, path, name, iconUrl),
	)
	return f.AddRouteProcessor(path, f.makeProcessorFromPageFile(path, filePath))
}

func (f *CFeature) AddGeneralPageProcessor(key, path, name, iconUrl string, processor feature.ReqProcessFn) MakeFeature {
	f.generalPages = append(
		f.generalPages,
		NewGeneralPage(key, path, name, iconUrl),
	)
	return f.AddRouteProcessor(path, processor)
}

func (f *CFeature) AddDashboardItemFromString(key, name, thumbnailUrl, description, path, raw string) MakeFeature {
	return f.AddDashboardItemFromStringWithConfig(key, name, thumbnailUrl, description, path, raw, "", "")
}

func (f *CFeature) AddDashboardItemFromStringWithConfig(key, name, thumbnailUrl, description, path, raw, configPath, configRaw string) MakeFeature {
	configurable := configPath != "" && configRaw != ""
	if strings.Contains(path, "?") {
		path += "&"
	} else {
		path += "?"
	}
	path += "dashboardId={dashboard.id}"
	path += "&dashboardItemId={dashboardItem.id}"
	path += "&dashboardItemKey={dashboardItem.key}"
	path += "&dashboardItemViewType={dashboardItem.viewType}"
	f.dashboardItems = append(
		f.dashboardItems,
		NewDashboardItem(key, path, name, thumbnailUrl, description, configurable),
	)
	if configurable {
		f.AddRouteProcessor(configPath, f.makeProcessorFromPageString(configPath, configRaw))
	}
	return f.AddRouteProcessor(path, f.makeProcessorFromPageString(path, raw))
}

func (f *CFeature) AddDashboardItemFromFile(key, name, thumbnailUrl, description, path, filePath string) MakeFeature {
	return f.AddDashboardItemFromFileWithConfig(key, name, thumbnailUrl, description, path, filePath, "", "")
}

func (f *CFeature) AddDashboardItemFromFileWithConfig(key, name, thumbnailUrl, description, path, filePath, configPath, configFile string) MakeFeature {
	configurable := configPath != "" && configFile != ""
	params := "dashboardId={dashboard.id}"
	params += "&dashboardItemId={dashboardItem.id}"
	params += "&dashboardItemKey={dashboardItem.key}"
	params += "&dashboardItemViewType={dashboardItem.viewType}"
	if strings.Contains(path, "?") {
		path += "&" + params
	} else {
		path += "?" + params
	}
	f.dashboardItems = append(
		f.dashboardItems,
		NewDashboardItem(key, path, name, thumbnailUrl, description, configurable),
	)
	if configurable {
		if strings.Contains(configPath, "?") {
			configPath += "&" + params
		} else {
			configPath += "?" + params
		}
		f.AddRouteProcessor(configPath, f.makeProcessorFromPageFile(configPath, configFile))
	}
	return f.AddRouteProcessor(path, f.makeProcessorFromPageFile(path, filePath))
}

func (f *CFeature) AddDashboardItemProcessor(key, path, name, thumbnailUrl, description string, processor feature.ReqProcessFn) MakeFeature {
	return f.AddDashboardItemProcessorWithConfig(key, path, name, thumbnailUrl, description, "", nil, processor)
}

func (f *CFeature) AddDashboardItemProcessorWithConfig(key, path, name, thumbnailUrl, description, configPath string, configProcessor, processor feature.ReqProcessFn) MakeFeature {
	configurable := configPath != "" && configProcessor != nil
	params := "dashboardId={dashboard.id}"
	params += "&dashboardItemId={dashboardItem.id}"
	params += "&dashboardItemKey={dashboardItem.key}"
	params += "&dashboardItemViewType={dashboardItem.viewType}"
	if strings.Contains(path, "?") {
		path += "&" + params
	} else {
		path += "?" + params
	}
	f.dashboardItems = append(
		f.dashboardItems,
		NewDashboardItem(key, path, name, thumbnailUrl, description, configurable),
	)
	if configurable {
		if strings.Contains(configPath, "?") {
			configPath += "&" + params
		} else {
			configPath += "?" + params
		}
		f.AddRouteProcessor(configPath, configProcessor)
	}
	return f.AddRouteProcessor(path, processor)
}

func (f *CFeature) AddConnectModule(name string, module interface{}) MakeFeature {
	if _, ok := f.descriptor.Modules[name]; ok {
		log.FatalDF(1, "gonnectian module exists already: %v", name)
		return nil
	}
	f.descriptor.Modules[name] = module
	return f
}

func (f *CFeature) AddRouteHandler(route string, handler http.Handler) MakeFeature {
	if _, ok := f.handlers[route]; ok {
		log.FatalDF(1, "gonnectian route handler exists already: %v", route)
		return nil
	}
	f.handlers[route] = handler
	return f
}

func (f *CFeature) AddRouteProcessor(route string, processor feature.ReqProcessFn) MakeFeature {
	if _, ok := f.processors[route]; ok {
		log.FatalDF(1, "gonnectian route processor exists already: %v", route)
		return nil
	}
	log.DebugF("adding gonnectian route processor for: %v", route)
	f.processors[route] = processor
	return f
}

func (f *CFeature) AddContentSecurityPolicyDirective(p csp.Directive) MakeFeature {
	f.cspDirectives = append(f.cspDirectives, p)
	return f
}

func (f *CFeature) Make() Feature {
	return f
}

func (f *CFeature) Tag() (tag feature.Tag) {
	tag = feature.Tag(strcase.ToKebab(string(Tag) + "-" + f.makeTag))
	return
}

func (f *CFeature) Build(b feature.Buildable) (err error) {
	b.AddFlags(
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-name",
			Usage:   "specify the Gonnectian Connect plugin name",
			EnvVars: []string{globals.EnvPrefix + "_AC_NAME_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-description",
			Usage:   "specify the Gonnectian Connect plugin description",
			EnvVars: []string{globals.EnvPrefix + "_AC_DESCRIPTION_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-key",
			Usage:   "specify the Gonnectian Connect plugin key",
			EnvVars: []string{globals.EnvPrefix + "_AC_KEY_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-version",
			Usage:   "specify the Gonnectian Connect plugin version",
			EnvVars: []string{globals.EnvPrefix + "_AC_VERSION_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-base-url",
			Usage:   "specify the Gonnectian Connect plugin base URL",
			EnvVars: []string{globals.EnvPrefix + "_AC_BASE_URL_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-base-route",
			Usage:   "specify the Gonnectian Connect plugin base route",
			EnvVars: []string{globals.EnvPrefix + "_AC_BASE_ROUTE_" + f.makeEnv},
		},
		&cli.StringSliceFlag{
			Name:    f.makeTag + "-ac-scope",
			Usage:   "specify the Gonnectian Connect plugin scopes",
			Value:   cli.NewStringSlice("READ"),
			EnvVars: []string{globals.EnvPrefix + "_AC_SCOPES_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-vendor-name",
			Usage:   "specify the Gonnectian Connect plugin vendor name",
			EnvVars: []string{globals.EnvPrefix + "_AC_VENDOR_NAME_" + f.makeEnv},
		},
		&cli.StringFlag{
			Name:    f.makeTag + "-ac-vendor-url",
			Usage:   "specify the Gonnectian Connect plugin vendor URL",
			EnvVars: []string{globals.EnvPrefix + "_AC_VENDOR_URL_" + f.makeEnv},
		},
		&cli.BoolFlag{
			Name:    f.makeTag + "-ac-validate-ip",
			Usage:   "restrict authenticated connections to valid Atlassian IP ranges",
			EnvVars: []string{globals.EnvPrefix + "_AC_VALIDATE_IP_" + f.makeEnv},
		},
	)
	return
}

func (f *CFeature) Setup(enjin feature.Internals) {
	f.CFeature.Setup(enjin)
}

func (f *CFeature) mustDB() (db *gorm.DB) {
	if v := f.Enjin.MustDB(f.dbTag); v != nil {
		var ok bool
		if db, ok = v.(*gorm.DB); !ok {
			log.PanicDF(1, "expected *gorm.DB, found: %T", v)
		}
	}
	return
}

func (f *CFeature) tx() (tx *gorm.DB) {
	tx = f.mustDB().Scopes(func(tx *gorm.DB) *gorm.DB {
		if f.dbTable != "" {
			return tx.Table(f.dbTable)
		}
		return tx
	})
	return
}

func (f *CFeature) Startup(ctx *cli.Context) (err error) {
	if err = f.CFeature.Startup(ctx); err != nil {
		return
	}

	_ = f.mustDB() // panic if expected database not present
	if ctx.IsSet(f.makeTag + "-ac-base-route") {
		if v := ctx.String(f.makeTag + "-ac-base-route"); v != "" {
			f.baseRoute = v
		}
	}
	if f.baseRoute == "" {
		f.baseRoute = "/"
	}
	f.baseRoute = "/" + bePath.TrimSlashes(f.baseRoute)

	if ctx.IsSet(f.makeTag + "-ac-name") {
		if v := ctx.String(f.makeTag + "-ac-name"); v != "" {
			f.descriptor.Name = v
		}
	}
	if f.descriptor.Name == "" {
		err = fmt.Errorf("missing --%v-ac-name", f.makeTag)
		return
	}

	if ctx.IsSet(f.makeTag + "-ac-key") {
		if v := ctx.String(f.makeTag + "-ac-key"); v != "" {
			f.descriptor.Key = v
		}
	}
	if f.descriptor.Key == "" {
		err = fmt.Errorf("missing --%v-ac-key", f.makeTag)
		return
	}

	f.descriptor.Description = ctx.String(f.makeTag + "-ac-description")
	if f.descriptor.Description == "" {
		err = fmt.Errorf("missing --%v-ac-description: %v", f.makeTag, ctx.String(f.makeTag+"-ac-description"))
		return
	}

	if ctx.IsSet(f.makeTag + "-ac-base-url") {
		if v := ctx.String(f.makeTag + "-ac-base-url"); v != "" {
			f.profile.BaseUrl = v
			log.DebugF("--%v-ac-base-url present: %v", f.makeTag, v)
		} else {
			log.DebugF("--%v-ac-base-url set, empty", f.makeTag)
		}
	} else {
		log.DebugF("--%v-ac-base-url not set", f.makeTag)
	}
	f.profile.BaseUrl = bePath.TrimTrailingSlash(f.profile.BaseUrl)
	f.descriptor.BaseURL = f.profile.BaseUrl
	if f.descriptor.BaseURL == "" {
		err = fmt.Errorf("missing --%v-ac-base-url", f.makeTag)
		return
	}

	if ctx.IsSet(f.makeTag + "-ac-vendor-name") {
		if v := ctx.String(f.makeTag + "-ac-vendor-name"); v != "" {
			f.descriptor.Vendor.Name = v
		}
	}
	if f.descriptor.Vendor.Name == "" {
		err = fmt.Errorf("missing --%v-ac-vendor-name", f.makeTag)
		return
	}

	if ctx.IsSet(f.makeTag + "-ac-vendor-url") {
		if v := ctx.String(f.makeTag + "-ac-vendor-url"); v != "" {
			f.descriptor.Vendor.URL = v
		}
	}
	if f.descriptor.Vendor.URL == "" {
		err = fmt.Errorf("missing --%v-ac-vendor-url", f.makeTag)
		return
	}

	if ctx.IsSet(f.makeTag + "-ac-version") {
		if v := ctx.String(f.makeTag + "-ac-version"); v != "" {
			f.descriptor.Version = v
		}
	}
	if f.descriptor.Version == "" {
		err = fmt.Errorf("missing --%v-ac-version", f.makeTag)
		return
	}

	if ctx.IsSet(f.makeTag + "-ac-validate-ip") {
		f.validateIp = ctx.Bool(f.makeTag + "-ac-validate-ip")
	}

	if ctx.IsSet(f.makeTag + "-ac-scope") {
		var scopes []string
		for _, v := range ctx.StringSlice(f.makeTag + "-ac-scope") {
			scope := strings.ToUpper(v)
			if !slices.Present(scope, scopes...) {
				scopes = append(scopes, scope)
			}
		}
		// command line overrides main.go ConnectScopes()
		f.descriptor.Scopes = scopes
	}

	var prefix, prefixLabel string
	if prefix = ctx.String("prefix"); prefix != "" && prefix != "prd" {
		prefixLabel = "[" + strings.ToUpper(prefix) + "] "
		f.descriptor.Name = prefixLabel + f.descriptor.Name
	}

	if len(f.generalPages) > 0 {
		var pages GeneralPages
		for _, p := range f.generalPages {
			if prefixLabel != "" {
				p.Name.Value = prefixLabel + p.Name.Value
			}
			p.Url = bePath.SafeConcatUrlPath(f.baseRoute, p.Url)
			pages = append(pages, p)
		}
		f.descriptor.Modules["generalPages"] = pages
	}

	if len(f.dashboardItems) > 0 {
		var items DashboardItems
		for _, p := range f.dashboardItems {
			if prefixLabel != "" {
				p.Name.Value = prefixLabel + p.Name.Value
			}
			p.Url = bePath.SafeConcatUrlPath(f.baseRoute, p.Url)
			items = append(items, p)
		}
		f.descriptor.Modules["jiraDashboardItems"] = items
	}

	f.descriptor.Authentication = Authentication{Type: "JWT"}
	f.descriptor.Lifecycle.Installed = bePath.JoinWithSlash(f.baseRoute, "installed")
	f.descriptor.Lifecycle.Enabled = bePath.JoinWithSlash(f.baseRoute, "enabled")
	f.descriptor.Lifecycle.Disabled = bePath.JoinWithSlash(f.baseRoute, "disabled")
	f.descriptor.Lifecycle.UnInstalled = bePath.JoinWithSlash(f.baseRoute, "uninstalled")

	var dm map[string]interface{}
	if dm, err = f.descriptor.ToMap(); err != nil {
		return
	}

	var s *store.Store
	if s, err = store.NewTableFrom(f.dbTable, f.mustDB()); err != nil {
		return
	}

	if f.addon, err = gonnect.NewCustomAddon(f.profile, fmt.Sprintf("%v-feature", f.makeTag), dm, s); err != nil {
		err = fmt.Errorf("error making gonnect.NewCustomAddon: %w", err)
		return
	}

	if f.validateIp {
		if f.ipRanges, err = atlassian.GetIpRanges(); err != nil {
			err = fmt.Errorf("error getting %v atlassian ip ranges: %w", f.makeName, err)
			return
		}
		log.DebugF("%v known %v atlassian ip ranges (--ac-validate-ip=true)", f.makeName, len(f.ipRanges))
	}

	log.InfoF("Atlassian Plugin URL [%v]: %v", f.makeName, f.GetPluginInstallationURL())

	return
}

func (f *CFeature) Action(verb string, details ...string) (action feature.Action) {
	action = feature.NewAction(f.Tag().Kebab(), verb, details...)
	return
}

func (f *CFeature) UserActions() (actions feature.Actions) {
	actions = actions.Append(
		f.Action("view", "page"),
	)
	return
}

func (f *CFeature) GetPluginInstallationURL() (url string) {
	url = bePath.TrimTrailingSlash(f.descriptor.BaseURL)
	if f.baseRoute != "" {
		url += f.baseRoute
	}
	url += "/atlassian-connect.json"
	return
}

func (f *CFeature) GetPluginDescriptor() (descriptor *Descriptor) {
	descriptor = f.descriptor.Copy()
	return
}

func (f *CFeature) Apply(s feature.System) (err error) {
	log.DebugF("applying %v atlassian routes: %v", f.makeName, f.baseRoute)

	routes.RegisterRoutes(
		f.baseRoute, f.addon, s.Router(),
		http.HandlerFunc(f.routeHandlerFn),
		f.connectDisabledHandler,
	)

	for route, handler := range f.handlers {
		log.DebugF("including %v atlassian custom route handler: %v", f.makeName, route)
		s.Router().Handle(route, middleware.NewAuthenticationMiddleware(f.addon, false)(handler))
	}

	return
}

func (f *CFeature) updateTenantRecord(r *http.Request, hostBaseUrl string, tenant *store.Tenant, tenantContext map[string]interface{}) (err error) {
	var license string
	if license = r.URL.Query().Get("lic"); license == "" {
		license = "none"
	}
	log.DebugF("tenant license is \"%v\"", license)
	tenantContext["license"] = license

	if license == "none" {
		if v, ok := tenantContext["allowed-unlicensed"].(bool); (ok && !v) || !ok {
			tenantContext["reject"] = "unlicensed"
			log.ErrorF("tenant is not allowed-unlicensed, must reject")
		} else {
			delete(tenantContext, "reject")
		}
	}

	var data []byte
	if data, err = json.Marshal(tenantContext); err != nil {
		err = fmt.Errorf("error marshalling json tenantContext: %v - %w", hostBaseUrl, err)
		return
	}

	tenant.Context = data
	if tenant, err = f.addon.Store.Set(tenant); err != nil {
		err = fmt.Errorf("error storing tenant on enabled: %v - %w", hostBaseUrl, err)
		return
	}
	return
}

func (f *CFeature) routeHandlerFn(w http.ResponseWriter, r *http.Request) {
	log.WarnF("route handler hit: %v", r.URL.Path)
	var err error
	var hostBaseUrl string
	var tenant *store.Tenant
	var tenantContext map[string]interface{}
	if hostBaseUrl, tenant, tenantContext, err = f.parseConnectRequest(r); err != nil {
		log.ErrorF("error parsing connect request: %v", err)
		serve.Serve404(w, r)
		return
	}

	// make a tenant context parsing wrapper func
	// update the license and store
	// pass tenant context to dashboard items, templates
	// if not allow-unlicensed, render gadget error content instead of ui

	// log.InfoF("tenant hit enabled handler: %v - %#+v - %#+v", hostBaseUrl, tenant, tenantContext)
	if q := r.URL.Query(); q != nil && q.Has("lic") {
		if err := f.updateTenantRecord(r, hostBaseUrl, tenant, tenantContext); err != nil {
			log.ErrorRF(r, "error updating tenant record: %w", err)
		}
		serve.Serve204(w, r)
		return
	}

	log.ErrorF("%v missing lic query parameter", f.makeName)
	serve.Serve404(w, r)
	return
}

func (f *CFeature) modifyContentSecurityPolicy(policy csp.Policy, r *http.Request) (modified csp.Policy) {
	var ok bool
	var hostBaseUrl string
	if hostBaseUrl, ok = r.Context().Value("hostBaseUrl").(string); !ok {
		log.ErrorF("%v missing hostBaseUrl", f.makeName)
		modified = policy
		// panic("critical error: request denied with 500 response")
		return
	}
	modified = csp.NewPolicy(
		append(policy.Directives(),
			csp.NewDefaultSrc(
				csp.Self,
				csp.UnsafeInline,
				csp.NewSchemeSource("data"),
				csp.NewSchemeSource("https"),
			),
			csp.NewScriptSrc(
				csp.Self,
				csp.UnsafeEval,
				csp.UnsafeInline,
				csp.NewSchemeSource("data"),
				csp.NewSchemeSource("https"),
				csp.NewHostSource(hostBaseUrl),
				csp.NewHostSource(f.profile.BaseUrl),
				csp.NewHostSource("*.atl-pass.net"),
				// csp.NewHostSource("connect-cdn.atl-pass.net"),
				// csp.NewHostSource("jira-frontend-static.prod.public.atl-paas.net"),
			),
			csp.NewFormAction(csp.Self),
			csp.NewFrameAncestors(csp.Self, csp.NewHostSource(hostBaseUrl)),
		)...,
	)
	for _, d := range f.cspDirectives {
		modified = modified.Add(d)
	}
	// log.DebugF("modified content security policy: %#+v", modified.Value())
	return
}

func (f *CFeature) Use(s feature.System) feature.MiddlewareFn {
	log.DebugF("including %v atlassian middleware", f.makeName)
	mw := middleware.NewRequestMiddleware(f.addon, make(map[string]string))
	return func(next http.Handler) http.Handler {
		this := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slices.Present(r.URL.Path, routes.RegisteredRoutes...) {
				if f.ipRejected(s, w, r) {
					address, _ := net.GetIpFromRequest(r)
					log.ErrorF("address denied by gonnectian IP restrictions: %v - %v", address, r.URL.String())
					return
				}
			}
			next.ServeHTTP(w, r)
		})
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw(this).ServeHTTP(w, r)
		})
	}
}

func (f *CFeature) FilterPageContext(ctx, _ beContext.Context, r *http.Request) (out beContext.Context) {
	if f.baseRoute != "" {
		ctx.SetSpecific("BaseRoute"+f.makeEnv, f.baseRoute)
	}
	if hostBaseUrl, ok := r.Context().Value("hostBaseUrl").(string); ok {
		ctx.SetSpecific("HostBaseUrl"+f.makeEnv, hostBaseUrl)
	}
	if hostStyleUrl, ok := r.Context().Value("hostStylesheetUrl").(string); ok {
		ctx.SetSpecific("HostStylesheetUrl"+f.makeEnv, hostStyleUrl)
	}
	if hostScriptUrl, ok := r.Context().Value("hostScriptUrl").(string); ok {
		ctx.SetSpecific("HostScriptUrl"+f.makeEnv, hostScriptUrl)
	}
	if debug, ok := r.Context().Value("debug").(string); ok {
		switch strings.ToLower(debug) {
		case "1", "on", "yes", "y", "true":
			ctx.SetSpecific("Debug", true)
		default:
			ctx.SetSpecific("Debug", false)
		}
	} else {
		ctx.SetSpecific("Debug", false)
	}
	if reject, ok := r.Context().Value("reject").(string); ok && reject != "" {
		ctx.SetSpecific("Reject", reject)
	}
	q := r.URL.Query()
	if v := q.Get("dashboardId"); v != "" {
		ctx.SetSpecific("DashboardId"+f.makeEnv, v)
	}
	if v := q.Get("dashboardItemId"); v != "" {
		ctx.SetSpecific("DashboardItemId"+f.makeEnv, v)
	}
	if v := q.Get("dashboardItemKey"); v != "" {
		ctx.SetSpecific("DashboardItemKey"+f.makeEnv, v)
	}
	if v := q.Get("dashboardItemViewType"); v != "" {
		ctx.SetSpecific("DashboardItemViewType"+f.makeEnv, v)
	}
	out = ctx
	return
}

func (f *CFeature) FindTenantByUrl(url string) (tenant *store.Tenant) {
	db := f.tx()
	tenant = &store.Tenant{}
	if err := db.Where("base_url = ?", url).First(tenant).Error; err != nil {
		log.ErrorF("error looking up tenant for %v: %v", url, err)
	}
	return
}

func (f *CFeature) Process(s feature.Service, next http.Handler, w http.ResponseWriter, r *http.Request) {
	for route, processor := range f.processors {
		if path := bePath.SafeConcatUrlPath(f.baseRoute, beForms.TrimQueryParams(route)); path == r.URL.Path {
			if hostBaseUrl, tenant, tenantContext, err := f.parseConnectRequest(r); err != nil {
				log.ErrorF("error parsing connect request: %v", err)
			} else {
				log.DebugF("running %v atlassian %v route processor for app host: %v", f.makeName, path, hostBaseUrl)

				if ee := f.updateTenantRecord(r, hostBaseUrl, tenant, tenantContext); ee != nil {
					log.ErrorRF(r, "error updating tenant record: %v", ee)
				}

				policy := s.ContentSecurityPolicy().GetRequestPolicy(r)
				// log.DebugF("modified content security policy [before] : %#+v", policy.Value())
				policy = f.modifyContentSecurityPolicy(policy, r)
				// log.DebugF("modified content security policy [after] : %#+v", policy.Value())
				r = s.ContentSecurityPolicy().SetRequestPolicy(r, policy)

				ctx := context.WithValue(r.Context(), "debug", tenantContext["debug"])
				if license, ok := tenantContext["license"].(string); ok && license == "none" {
					if allowedUnlicensed, ok := tenantContext["allowed-unlicensed"].(bool); (ok && !allowedUnlicensed) || !ok {
						ctx = context.WithValue(ctx, "reject", "unlicensed")
						log.ErrorF("rejecting unlicensed tenant: %v - %#+v", hostBaseUrl, tenantContext)
					}
				}

				r = r.Clone(ctx)
				if processor(s, w, r) {
					log.DebugF("route handled: %v", path)
					f.Enjin.Emit(SignalRouteHandled, f.Tag().Kebab(), r, hostBaseUrl, tenantContext)
					return
				}
				log.DebugF("route not handled: %v", path)
			}
		}
	}
	// log.DebugF("not an atlassian route: %v", r.URL.Path)
	next.ServeHTTP(w, r)
}

func (f *CFeature) ipRejected(s feature.Service, w http.ResponseWriter, r *http.Request) bool {
	if f.validateIp && !net.CheckRequestIpWithList(r, f.ipRanges) {
		s.Serve403(w, r)
		address, _ := net.GetIpFromRequest(r)
		log.WarnF("%v atlassian request denied - not from a known atlassian ip range: %v", f.makeName, address)
		return true
	}
	return false
}

func (f *CFeature) makeProcessorFromPageFile(path string, filePath string) feature.ReqProcessFn {
	return func(s feature.Service, w http.ResponseWriter, r *http.Request) (ok bool) {
		var err error
		var data []byte
		var p feature.Page
		theme, _ := f.Enjin.GetTheme()

		if data, err = os.ReadFile(filePath); err == nil {

			var created, updated int64
			if info, e := times.Stat(filePath); e == nil {
				updated = info.ModTime().Unix()
				if info.HasBirthTime() {
					created = info.BirthTime().Unix()
				} else {
					created = updated
				}
			} else {
				log.ErrorF("%v feature: error getting timestamps from file: %v - %v", filePath, e)
				created = time.Now().Unix()
				updated = created
			}

			if p, err = page.New(f.Tag().String(), filePath, string(data), created, updated, theme, f.Enjin.Context(r)); err == nil {
				if err = s.ServePage(p, w, r); err != nil {
					log.ErrorF("error serving %v atlassian page %v: %v", f.makeName, r.URL.Path, err)
				}
			} else {
				log.ErrorF("error making %v atlassian page from path: %v", f.makeName, err)
			}

		} else {
			log.ErrorF("error reading file: %v - %v", filePath, err)
		}
		return err == nil
	}
}

func (f *CFeature) makeProcessorFromPageString(path string, raw string) feature.ReqProcessFn {
	var p feature.Page
	var err error
	var created, updated int64
	if info, e := globals.BuildFileInfo(); e == nil {
		updated = info.ModTime().Unix()
		if info.HasBirthTime() {
			created = info.BirthTime().Unix()
		} else {
			created = updated
		}
	} else {
		created = time.Now().Unix()
		updated = created
	}
	theme, _ := f.Enjin.GetTheme()
	if p, err = page.New(f.Tag().String(), path, raw, created, updated, theme, f.enjin.Context()); err != nil {
		log.FatalF("error making %v atlassian page from path: %v", f.makeName, err)
	}
	return func(s feature.Service, w http.ResponseWriter, r *http.Request) (ok bool) {
		if err = s.ServePage(p, w, r); err != nil {
			log.ErrorF("error serving %v atlassian page %v: %v", f.makeName, r.URL.Path, err)
		}
		return err == nil
	}
}

func (f *CFeature) parseConnectRequest(r *http.Request) (hostBaseUrl string, tenant *store.Tenant, tenantContext map[string]interface{}, err error) {
	var ok bool
	if hostBaseUrl, ok = r.Context().Value("hostBaseUrl").(string); !ok || hostBaseUrl == "" {
		err = fmt.Errorf("%v missing hostBaseUrl", f.makeName)
		return
	}
	if tenant = f.FindTenantByUrl(hostBaseUrl); tenant == nil {
		err = fmt.Errorf("%v tenant not found", f.makeName)
		return
	}

	var license string
	if license, ok = r.Context().Value("license").(string); !ok || license == "" {
		license = "none"
	}

	var jsonData string
	if jsonData, ok = r.Context().Value("tenantContext").(string); !ok {
		err = fmt.Errorf("%v missing tenantContext", f.makeName)
		return
	}
	if jsonData == "" {
		jsonData = "{}"
	}
	if err = json.Unmarshal([]byte(jsonData), &tenantContext); err != nil {
		err = fmt.Errorf("error parsing tenant context json: %v - %v", f.makeName, err)
		return
	}

	tenantContext["license"] = license
	return
}