package opentracing

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"
	"inet.af/netaddr"
	"net"
	"net/http"
	"regexp"
	"strings"
)

var (
	defaultServiceName  = "gin.router"
	ipv6SpecialNetworks = []*netaddr.IPPrefix{
		ippref("fec0::/10"), // site local
	}

	defaultIPHeaders = []string{
		"x-forwarded-for",
		"x-real-ip",
		"x-client-ip",
		"x-forwarded",
		"x-cluster-client-ip",
		"forwarded-for",
		"forwarded",
		"via",
		"true-client-ip",
	}

	defaultRegexString = "(?i)(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?|private_?|public_?|access_?|secret_?)key(?:_?id)?|token|consumer_?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?)(?:(?:\\s|%20)*(?:=|%3D)[^&]+|(?:\"|%22)(?:\\s|%20)*(?::|%3A)(?:\\s|%20)*(?:\"|%22)(?:%2[^2]|%[^2]|[^\"%])+(?:\"|%22))|bearer(?:\\s|%20)+[a-z0-9\\._\\-]|token(?::|%3A)[a-z0-9]{13}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L](?:[\\w=-]|%3D)+\\.ey[I-L](?:[\\w=-]|%3D)+(?:\\.(?:[\\w.+\\/=-]|%3D|%2F|%2B)+)?|[\\-]{5}BEGIN(?:[a-z\\s]|%20)+PRIVATE(?:\\s|%20)KEY[\\-]{5}[^\\-]+[\\-]{5}END(?:[a-z\\s]|%20)+PRIVATE(?:\\s|%20)KEY|ssh-rsa(?:\\s|%20)*(?:[a-z0-9\\/\\.+]|%2F|%5C|%2B){100,}"
)

const (
	ExtServiceName  = "service.name"
	ExtResourceName = "resource.name"
	// HTTPRoute is the route value of the HTTP request.
	ExtHTTPRoute = "http.route"

	// HTTPMethod specifies the HTTP method used in a span.
	ExtHTTPMethod = "http.method"

	// HTTPURL sets the HTTP URL for a span.
	ExtHTTPURL = "http.url"

	// HTTPUserAgent is the user agent header value of the HTTP request.
	ExtHTTPUserAgent = "http.useragent"

	ExtHTTPHost = "http.host"

	// HTTPClientIP sets the HTTP client IP tag.
	ExtHTTPClientIP = "http.client_ip"

	// HTTPRequestHeaders sets the HTTP request headers partial tag
	// This tag is meant to be composed, i.e http.request.headers.headerX, http.request.headers.headerY, etc...
	ExtHTTPRequestHeaders = "http.request.headers"

	ExtTmpl = "go.template"

	// SpanType defines the Span type (web, db, cache).
	ExtSpanType = "span.type"
	SpanTypeWeb = "web"
)

type (
	Skipper func(c *gin.Context) bool

	ResourceNamerFunc func(c *gin.Context) string

	// RecoverConfig defines the config for Recover middleware.
	TracerConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper                Skipper
		ResourceNamer          ResourceNamerFunc
		ServiceName            string
		ClientIPHeader         string
		ClientIPHeaderDisabled bool
		QueryStringRegexp      string
		QueryStringDisabled    bool
	}
)

var (
	// DefaultTracerConfig is the default opentracing middleware config.
	DefaultTracerConfig = TracerConfig{
		Skipper:       DefaultSkipper,
		ResourceNamer: DefaultResourceNamer,
	}
)

func DefaultResourceNamer(c *gin.Context) string {
	// getName is a hacky way to check whether *gin.Context implements the FullPath()
	// method introduced in v1.4.0, falling back to the previous implementation otherwise.
	getName := func(req *http.Request, c interface{ HandlerName() string }) string {
		if fp, ok := c.(interface {
			FullPath() string
		}); ok {
			return req.Method + " " + fp.FullPath()
		}
		return c.HandlerName()
	}
	return getName(c.Request, c)
}

func DefaultSkipper(c *gin.Context) bool {
	return false
}

// Tracer returns a middleware which records http activity in Opentracing Spans.
func Tracer() gin.HandlerFunc {
	return TracerWithConfig(DefaultTracerConfig)
}

// TracerWithConfig returns a Tracer middleware with config.
// See: `Tracer()`.
func TracerWithConfig(config TracerConfig) gin.HandlerFunc {
	if config.Skipper == nil {
		config.Skipper = DefaultTracerConfig.Skipper
	}

	if config.ServiceName == "" {
		config.ServiceName = defaultServiceName
	}

	exp := regexp.MustCompile(defaultRegexString)

	if config.QueryStringRegexp != "" {
		if r, err := regexp.Compile(config.QueryStringRegexp); err == nil {
			exp = r
		}
	}

	ipHeaders := defaultIPHeaders
	if len(config.ClientIPHeader) > 0 {
		ipHeaders = []string{config.ClientIPHeader}
	}

	spanOpts := []opentracing.StartSpanOption{
		opentracing.Tag{Key: ExtServiceName, Value: config.ServiceName},
	}

	return func(c *gin.Context) {
		if config.Skipper(c) {
			c.Next()
		}
		r := c.Request
		opts := append(spanOpts, opentracing.Tag{Key: ExtResourceName, Value: config.ResourceNamer(c)})
		opts = append(opts, opentracing.Tag{Key: ExtHTTPRoute, Value: c.FullPath()})
		opts = append([]opentracing.StartSpanOption{
			opentracing.Tag{Key: ExtSpanType, Value: SpanTypeWeb},
			opentracing.Tag{Key: ExtHTTPMethod, Value: r.Method},
			opentracing.Tag{Key: ExtHTTPURL, Value: urlFromRequest(r, config.QueryStringDisabled, exp)},
			opentracing.Tag{Key: ExtHTTPUserAgent, Value: r.UserAgent()},
		}, opts...)
		if r.Host != "" {
			opts = append([]opentracing.StartSpanOption{
				opentracing.Tag{Key: ExtHTTPHost, Value: r.Host},
			}, opts...)
		}
		if !config.ClientIPHeaderDisabled {
			opts = append(genClientIPSpanTags(r, ipHeaders), opts...)
		}

		if spanctx, err := extract(opentracing.HTTPHeadersCarrier(r.Header)); err == nil {
			opts = append(opts, opentracing.ChildOf(spanctx))
		}

		span, ctx := opentracing.StartSpanFromContext(r.Context(), "http.request", opts...)
		defer func() {
			status := c.Writer.Status()
			ext.HTTPStatusCode.Set(span, uint16(status))
			if status >= 500 && status < 600 {
				ext.Error.Set(span, true)
				span.LogFields(log.Error(fmt.Errorf("%v: %s", status, http.StatusText(status))))
			}
		}()

		c.Request = c.Request.WithContext(ctx)

		c.Next()

		if len(c.Errors) > 0 {
			ext.Error.Set(span, true)
			for _, e := range c.Errors {
				span.LogFields(log.Error(e))
			}
		}
	}
}

// HTML will trace the rendering of the template as a child of the span in the given context.
func HTML(c *gin.Context, code int, name string, obj interface{}) {
	span, _ := opentracing.StartSpanFromContext(c.Request.Context(), "gin.render.html")
	span.SetTag("go.template", name)
	defer func() {
		if r := recover(); r != nil {
			ext.Error.Set(span, true)
			err := fmt.Errorf("error rendering tmpl:%s: %s", name, r)
			span.LogFields(log.Error(err))
			panic(r)
		} else {
			span.Finish()
		}
	}()
	c.HTML(code, name, obj)
}

func extract(carrier interface{}) (opentracing.SpanContext, error) {
	return opentracing.GlobalTracer().Extract(opentracing.HTTPHeaders, carrier)
}

// ippref returns the IP network from an IP address string s. If not possible, it returns nil.
func ippref(s string) *netaddr.IPPrefix {
	if prefix, err := netaddr.ParseIPPrefix(s); err == nil {
		return &prefix
	}
	return nil
}

// urlFromRequest returns the full URL from the HTTP request. If query params are collected, they are obfuscated granted
// obfuscation is not disabled by the user.
func urlFromRequest(r *http.Request, queryStringDisabled bool, exp *regexp.Regexp) string {
	// Quoting net/http comments about net.Request.URL on server requests:
	// "For most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)"
	// This is why we don't rely on url.URL.String(), url.URL.Host, url.URL.Scheme, etc...
	var url string
	path := r.URL.EscapedPath()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.Host != "" {
		url = strings.Join([]string{scheme, "://", r.Host, path}, "")
	} else {
		url = path
	}
	// Collect the query string if we are allowed to report it and obfuscate it if possible/allowed
	if (!queryStringDisabled) && r.URL.RawQuery != "" {
		query := r.URL.RawQuery
		if exp != nil {
			query = exp.ReplaceAllLiteralString(query, "<redacted>")
		}
		url = strings.Join([]string{url, query}, "?")
	}
	if frag := r.URL.EscapedFragment(); frag != "" {
		url = strings.Join([]string{url, frag}, "#")
	}
	return url
}

// genClientIPSpanTags generates the client IP related tags that need to be added to the span.
func genClientIPSpanTags(r *http.Request, ipHeaders []string) []opentracing.StartSpanOption {
	var headers []string
	var ips []string
	var opts []opentracing.StartSpanOption
	for _, hdr := range ipHeaders {
		if v := r.Header.Get(hdr); v != "" {
			headers = append(headers, hdr)
			ips = append(ips, v)
		}
	}
	if len(ips) == 0 {
		if remoteIP := parseIP(r.RemoteAddr); remoteIP.IsValid() && isGlobal(remoteIP) {
			opts = append(opts, opentracing.Tag{Key: ExtHTTPClientIP, Value: remoteIP.String()})
		}
	} else if len(ips) == 1 {
		for _, ipstr := range strings.Split(ips[0], ",") {
			ip := parseIP(strings.TrimSpace(ipstr))
			if ip.IsValid() && isGlobal(ip) {
				opts = append(opts, opentracing.Tag{Key: ExtHTTPClientIP, Value: ip.String()})
				break
			}
		}
	} else {
		for i := range ips {
			opts = append(opts, opentracing.Tag{Key: ExtHTTPRequestHeaders + "." + headers[i], Value: ips[i]})
		}
	}
	return opts
}

func parseIP(s string) netaddr.IP {
	if ip, err := netaddr.ParseIP(s); err == nil {
		return ip
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		if ip, err := netaddr.ParseIP(h); err == nil {
			return ip
		}
	}
	return netaddr.IP{}
}

func isGlobal(ip netaddr.IP) bool {
	// IsPrivate also checks for ipv6 ULA.
	// We care to check for these addresses are not considered public, hence not global.
	// See https://www.rfc-editor.org/rfc/rfc4193.txt for more details.
	isGlobal := !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	if !isGlobal || !ip.Is6() {
		return isGlobal
	}
	for _, n := range ipv6SpecialNetworks {
		if n.Contains(ip) {
			return false
		}
	}
	return isGlobal
}
