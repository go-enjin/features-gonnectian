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
	goContext "context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/urfave/cli/v2"

	databaseFeature "github.com/go-enjin/be/features/database"
	"github.com/go-enjin/be/pkg/context"
	"github.com/go-enjin/be/pkg/database"
	"github.com/go-enjin/be/pkg/feature"
	beForms "github.com/go-enjin/be/pkg/forms"
	"github.com/go-enjin/be/pkg/globals"
	"github.com/go-enjin/be/pkg/hash/sha"
	"github.com/go-enjin/be/pkg/log"
	"github.com/go-enjin/be/pkg/net"
	"github.com/go-enjin/be/pkg/net/headers/policy/csp"
	"github.com/go-enjin/be/pkg/net/ip/ranges/atlassian"
	"github.com/go-enjin/be/pkg/page"
	bePath "github.com/go-enjin/be/pkg/path"
	beStrings "github.com/go-enjin/be/pkg/strings"

	gonnect "github.com/go-enjin/github-com-craftamap-atlas-gonnect"
	"github.com/go-enjin/github-com-craftamap-atlas-gonnect/middleware"
	"github.com/go-enjin/github-com-craftamap-atlas-gonnect/routes"
	"github.com/go-enjin/github-com-craftamap-atlas-gonnect/store"
)

var (
	_ Feature     = (*CFeature)(nil)
	_ MakeFeature = (*CFeature)(nil)
)

const Tag feature.Tag = "Gonnectian"

type Feature interface {
	feature.Feature
	feature.Middleware
	feature.PageContextModifier
	feature.ContentSecurityPolicyModifier
}

type CFeature struct {
	feature.CMiddleware

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

	enjin feature.Internals

	addon *gonnect.Addon

	cspDirectives []csp.Directive
}

type MakeFeature interface {
	feature.MakeFeature

	EnableIpValidation(enabled bool) MakeFeature
	ProfileBaseUrl(baseUrl string) MakeFeature
	ProfileBaseRoute(mount string) MakeFeature
	ProfileSignedInstall(signedInstall bool) MakeFeature

	ConnectFromJSON(encoded []byte) MakeFeature
	ConnectInfo(name, key, description, baseUrl string) MakeFeature
	ConnectVendor(name, url string) MakeFeature
	ConnectScopes(scopes ...string) MakeFeature
	ConnectInstalledPath(path string) MakeFeature
	ConnectUnInstalledPath(path string) MakeFeature
	ConnectEnabledPath(path string) MakeFeature
	ConnectDisabledPath(path string) MakeFeature
	ConnectApiVersion(apiVersion int) MakeFeature
	ConnectLicensing(enable bool) MakeFeature

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

func New(name, tag, env string) MakeFeature {
	if name == "" || tag == "" || env == "" {
		log.FatalF("gonnectian feature requires non-empty name, tag and env arguments")
		return nil
	}
	f := new(CFeature)
	f.makeName = name
	f.makeTag = tag
	f.makeEnv = env
	log.DebugF("new gonnectian feature: %v %v", f.makeTag, f.makeEnv)
	f.Init(f)
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
		log.FatalF("error decoding %v gonnectian json descriptor: %v", f.makeName, err)
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
		if !beStrings.StringInStrings(scope, f.descriptor.Scopes...) {
			f.descriptor.Scopes = append(
				f.descriptor.Scopes,
				scope,
			)
		}
	}
	return f
}

func (f *CFeature) ConnectInstalledPath(path string) MakeFeature {
	f.descriptor.Lifecycle.Installed = path
	return f
}

func (f *CFeature) ConnectUnInstalledPath(path string) MakeFeature {
	f.descriptor.Lifecycle.UnInstalled = path
	return f
}

func (f *CFeature) ConnectEnabledPath(path string) MakeFeature {
	f.descriptor.Lifecycle.Enabled = path
	return f
}

func (f *CFeature) ConnectDisabledPath(path string) MakeFeature {
	f.descriptor.Lifecycle.Disabled = path
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
		log.FatalF("gonnectian module exists already: %v", name)
		return nil
	}
	f.descriptor.Modules[name] = module
	return f
}

func (f *CFeature) AddRouteHandler(route string, handler http.Handler) MakeFeature {
	if _, ok := f.handlers[route]; ok {
		log.FatalF("gonnectian route handler exists already: %v", route)
		return nil
	}
	f.handlers[route] = handler
	return f
}

func (f *CFeature) AddRouteProcessor(route string, processor feature.ReqProcessFn) MakeFeature {
	if _, ok := f.processors[route]; ok {
		log.FatalF("gonnectian route processor exists already: %v", route)
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

func (f *CFeature) Init(this interface{}) {
	f.CMiddleware.Init(this)
	f.profile = new(gonnect.Profile)
	f.descriptor = NewDescriptor()
	f.descriptor.APIMigrations.SignedInstall = true
	f.descriptor.Version = globals.Version
	f.generalPages = make(GeneralPages, 0)
	f.dashboardItems = make(DashboardItems, 0)
	f.handlers = make(map[string]http.Handler)
	f.processors = make(map[string]feature.ReqProcessFn)
}

func (f *CFeature) Tag() (tag feature.Tag) {
	tag = feature.Tag(strcase.ToKebab(string(Tag) + "-" + f.makeTag))
	return
}

func (f *CFeature) Depends() (deps feature.Tags) {
	deps = feature.Tags{
		databaseFeature.Tag,
	}
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
	f.enjin = enjin
}

func (f *CFeature) Startup(ctx *cli.Context) (err error) {
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
			if !beStrings.StringInStrings(scope, scopes...) {
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
	f.descriptor.Lifecycle.UnInstalled = bePath.JoinWithSlash(f.baseRoute, "uninstalled")

	var dm map[string]interface{}
	if dm, err = f.descriptor.ToMap(); err != nil {
		return
	}
	var s *store.Store
	if s, err = store.NewFrom(database.Instance); err != nil {
		return
	}

	f.addon, err = gonnect.NewCustomAddon(f.profile, fmt.Sprintf("%v-feature", f.makeTag), dm, s)

	if f.validateIp {
		if f.ipRanges, err = atlassian.GetIpRanges(); err != nil {
			log.FatalF("error getting %v atlassian ip ranges: %v", f.makeName, err)
		}
		log.DebugF("%v known %v atlassian ip ranges (--ac-validate-ip=true)", f.makeName, len(f.ipRanges))
	}

	log.InfoF("Atlassian Plugin URL [%v]: %v", f.makeName, f.GetPluginInstallationURL())

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
	log.DebugF("applying %v atlassian routes", f.makeName)
	routes.RegisterRoutes(f.baseRoute, f.addon, s.Router())
	for route, handler := range f.handlers {
		log.DebugF("including %v atlassian custom route handler: %v", f.makeName, route)
		s.Router().Handle(route, middleware.NewAuthenticationMiddleware(f.addon, false)(handler))
	}
	return
}

func (f *CFeature) ModifyContentSecurityPolicy(policy csp.Policy, r *http.Request) (modified csp.Policy) {
	var ok bool
	var hostBaseUrl string
	if hostBaseUrl, ok = r.Context().Value("hostBaseUrl").(string); !ok {
		log.ErrorF("%v missing hostBaseUrl", f.makeName)
		modified = policy
		return
	}
	modified = csp.NewPolicy(
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
	)
	for _, d := range f.cspDirectives {
		modified = modified.Add(d)
	}
	log.DebugF("modified content security policy: %#+v", modified.Value())
	return
}

func (f *CFeature) Use(s feature.System) feature.MiddlewareFn {
	log.DebugF("including %v atlassian middleware", f.makeName)

	mw := middleware.NewRequestMiddleware(f.addon, make(map[string]string))
	return func(next http.Handler) http.Handler {
		this := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if beStrings.StringInStrings(r.URL.Path, routes.RegisteredRoutes...) {
				if f.ipRejected(s, w, r) {
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

func (f *CFeature) FilterPageContext(ctx, _ context.Context, r *http.Request) (out context.Context) {
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
	db := database.MustGet()
	tenant = &store.Tenant{}
	if err := db.Where("base_url = ?", url).First(tenant).Error; err != nil {
		log.ErrorF("error looking up tenant for %v: %v", url, err)
	}
	return
}

func (f *CFeature) Process(s feature.Service, next http.Handler, w http.ResponseWriter, r *http.Request) {
	for route, processor := range f.processors {
		if path := bePath.SafeConcatUrlPath(f.baseRoute, beForms.TrimQueryParams(route)); path == r.URL.Path {
			if hostBaseUrl, ok := r.Context().Value("hostBaseUrl").(string); ok && hostBaseUrl != "" {
				if jsonData, ok := r.Context().Value("tenantContext").(string); ok {
					var tenantContext map[string]interface{}
					if jsonData == "" {
						jsonData = "{}"
					}
					if err := json.Unmarshal([]byte(jsonData), &tenantContext); err != nil {
						log.ErrorF("error parsing tenant context json: %v", err)
					} else {
						log.DebugF("running %v atlassian %v route processor for app host: %v", f.makeName, path, hostBaseUrl)
						ctx := goContext.WithValue(r.Context(), "debug", tenantContext["debug"])
						if processor(s, w, r.WithContext(ctx)) {
							return
						}
					}
				} else {
					log.ErrorF("skipping unknown tenant by base url: %v", hostBaseUrl)
				}
			} else {
				log.WarnF("unauthenticated request for valid %v atlassian route: %v", f.makeName, path)
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
		var p *page.Page
		theme, _ := f.enjin.GetTheme()
		if p, err = page.NewFromFile(path, filePath, theme, f.enjin.Context()); err == nil {
			if err = s.ServePage(p, w, r); err != nil {
				log.ErrorF("error serving %v atlassian page %v: %v", f.makeName, r.URL.Path, err)
			}
		} else {
			log.ErrorF("error making %v atlassian page from path: %v", f.makeName, err)
		}
		return err == nil
	}
}

func (f *CFeature) makeProcessorFromPageString(path string, raw string) feature.ReqProcessFn {
	var p *page.Page
	var err error
	var created, updated int64
	if info, err := globals.BuildFileInfo(); err == nil {
		if info.HasBirthTime() {
			created = info.BirthTime().Unix()
		}
		updated = info.ModTime().Unix()
	}
	shasum, _ := sha.DataHash10([]byte(raw))
	theme, _ := f.enjin.GetTheme()
	if p, err = page.New(path, raw, shasum, created, updated, theme, f.enjin.Context()); err != nil {
		log.FatalF("error making %v atlassian page from path: %v", f.makeName, err)
	}
	return func(s feature.Service, w http.ResponseWriter, r *http.Request) (ok bool) {
		if err = s.ServePage(p, w, r); err != nil {
			log.ErrorF("error serving %v atlassian page %v: %v", f.makeName, r.URL.Path, err)
		}
		return err == nil
	}
}