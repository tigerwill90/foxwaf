// Copyright 2024 Sylvain Müller.
// SPDX-License-Identifier: Apache-2.0

// Part of the code in this package is derivative of https://github.com/corazawaf/coraza (all credit to Juan Pablo Tosso
// and the OWASP Coraza contributors). Mount of this source code is governed by an Apache-2.0 that can be found
// at https://github.com/corazawaf/coraza/blob/main/LICENSE.

package foxcoraza

import (
	"embed"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/tigerwill90/fox"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var p = sync.Pool{
	New: func() any {
		return &rwInterceptor{}
	},
}

//go:embed coraza/*
var coreRulesetFS embed.FS

func Middleware(waf coraza.WAF) fox.MiddlewareFunc {
	return NewWAF(waf).Intercept
}

type WAF struct {
	waf coraza.WAF
}

func NewCoreRulesetConfig(logger debuglog.Logger) coraza.WAFConfig {
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile("coraza/coraza.conf").
		WithDirectivesFromFile("coraza/coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("coraza/coreruleset/rules/*.conf").
		WithDebugLogger(debuglog.Default()).
		WithRootFS(coreRulesetFS)

	if logger != nil {
		cfg = cfg.WithDebugLogger(logger)
	}
	return cfg
}

func NewWAF(waf coraza.WAF) *WAF {
	return &WAF{
		waf: waf,
	}
}

func (w *WAF) Intercept(next fox.HandlerFunc) fox.HandlerFunc {
	newTX := func(*http.Request) types.Transaction {
		return w.waf.NewTransaction()
	}

	if ctxwaf, ok := w.waf.(experimental.WAFWithOptions); ok {
		newTX = func(r *http.Request) types.Transaction {
			return ctxwaf.NewTransactionWithOptions(experimental.Options{
				Context: r.Context(),
			})
		}
	}

	return func(c fox.Context) {
		req := c.Request()
		tx := newTX(req)
		defer func() {
			// We run phase 5 rules and create audit logs (if enabled)
			tx.ProcessLogging()
			// we remove temporary files and free some memory
			if err := tx.Close(); err != nil {
				tx.DebugLogger().Error().Err(err).Msg("Failed to close the transaction")
			}
		}()

		// Early return, Coraza is not going to process any rule
		if tx.IsRuleEngineOff() {
			next(c)
			return
		}

		// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
		// ProcessRequestHeaders and ProcessRequestBody.
		// It fails if any of these functions returns an error and it stops on interruption.
		if it, err := processRequest(tx, req); err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to process request")
			return
		} else if it != nil {
			c.Writer().WriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK))
			return
		}

		interceptor := p.Get().(*rwInterceptor)
		defer p.Put(interceptor)

		interceptor.reset(tx, c.Writer(), req.Proto)
		cc := c.CloneWith(interceptor, req)
		defer cc.Close()

		next(cc)

		if err := processResponse(tx, interceptor); err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to close the response")
			return
		}
	}
}

// processRequest fills all transaction variables from an http.Request object. Most implementations of Coraza will probably
// use http.Request objects so this will implement all phase 0, 1 and 2 variables.
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	// Host will always be removed from req.Headers() and promoted to the
	// Request.Host field, so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(req.Host)
	}

	// Transfer-Encoding header is removed by go/http
	// We manually add it to make rules relying on it work (E.g. CRS rule 920171)
	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}

	if tx.IsRequestBodyAccessible() {
		// We only do body buffering if the transaction requires request
		// body inspection, otherwise we just let the request follow its
		// regular flow.
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to append request body: %s", err.Error())
			}

			if it != nil {
				return it, nil
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return nil, fmt.Errorf("failed to get the request body: %s", err.Error())
			}

			// Adds all remaining bytes beyond the coraza limit to its buffer
			// It happens when the partial body has been processed and it did not trigger an interruption
			body := io.MultiReader(rbr, req.Body)
			// req.Body is transparently reinizialied with a new io.ReadCloser.
			// The http handler will be able to read it.
			// Prior to Go 1.19 NopCloser does not implement WriterTo if the reader implements it.
			// - https://github.com/golang/go/issues/51566
			// - https://tip.golang.org/doc/go1.19#minor_library_changes
			// This avoid errors like "failed to process request: malformed chunked encoding" when
			// using io.Copy.
			// In Go 1.19 we just do `req.Body = io.NopCloser(reader)`
			if rwt, ok := body.(io.WriterTo); ok {
				req.Body = struct {
					io.Reader
					io.WriterTo
					io.Closer
				}{body, rwt, req.Body}
			} else {
				req.Body = struct {
					io.Reader
					io.Closer
				}{body, req.Body}
			}
		}
	}

	return tx.ProcessRequestBody()
}

// processResponse takes care of the response body copyback from the transaction buffer.
func processResponse(tx types.Transaction, i *rwInterceptor) error {
	// We look for interruptions triggered at phase 3 (response headers)
	// and during writing the response body. If so, response status code
	// has been sent over the flush already.
	if tx.IsInterrupted() {
		return nil
	}

	if tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
		if it, err := tx.ProcessResponseBody(); err != nil {
			i.overrideWriteHeader(http.StatusInternalServerError)
			i.flushWriteHeader()
			return err
		} else if it != nil {
			// if there is an interruption we must clean the headers and override the status code
			i.cleanHeaders()
			i.Header().Set("Content-Length", "0")
			i.overrideWriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode))
			i.flushWriteHeader()
			return nil
		}

		// we release the buffer
		reader, err := tx.ResponseBodyReader()
		if err != nil {
			i.overrideWriteHeader(http.StatusInternalServerError)
			i.flushWriteHeader()
			return fmt.Errorf("failed to release the response body reader: %v", err)
		}

		// this is the last opportunity we have to report the resolved status code
		// as next step is write into the response writer (triggering a 200 in the
		// response status code.)
		i.flushWriteHeader()
		if _, err := io.Copy(i.w, reader); err != nil {
			return fmt.Errorf("failed to copy the response body: %v", err)
		}
	} else {
		i.flushWriteHeader()
	}

	return nil
}

// obtainStatusCodeFromInterruptionOrDefault returns the desired status code derived from the interruption
// on a "deny" action or a default value.
func obtainStatusCodeFromInterruptionOrDefault(it *types.Interruption, defaultStatusCode int) int {
	if it.Action == "deny" {
		statusCode := it.Status
		if statusCode == 0 {
			statusCode = 403
		}

		return statusCode
	}
	return defaultStatusCode
}

func relevantCaller() runtime.Frame {
	pc := make([]uintptr, 16)
	n := runtime.Callers(1, pc)
	frames := runtime.CallersFrames(pc[:n])
	var frame runtime.Frame
	for {
		f, more := frames.Next()
		if !strings.HasPrefix(f.Function, "github.com/tigerwill90/foxcoraza.") {
			return f
		}
		if !more {
			break
		}
	}
	return frame
}
