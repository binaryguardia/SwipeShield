// Package grpcproto implements schema-aware, field-level inspection of gRPC
// request bodies. Operators supply .proto files; the registry compiles them
// at runtime and resolves the incoming method to its input message type, so
// rules run against named fields rather than an opaque binary blob.
package grpcproto

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/binaryguardia/sentinelwaf/internal/decision"
)

// Registry compiles and indexes protobuf schemas.
type Registry struct {
	mu      sync.RWMutex
	methods map[string]protoreflect.MethodDescriptor // key: /pkg.Service/Method
	types   *protoregistry.Types
}

// NewRegistry compiles all .proto files under the given dirs.
func NewRegistry(ctx context.Context, schemaDirs []string, importDirs []string) (*Registry, error) {
	r := &Registry{
		methods: make(map[string]protoreflect.MethodDescriptor),
		types:   &protoregistry.Types{},
	}
	if len(schemaDirs) == 0 {
		return r, nil
	}
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			ImportPaths: append(importDirs, schemaDirs...),
		}),
	}
	// Collect proto files as paths relative to a schema/import dir so the
	// SourceResolver resolves them against its ImportPaths (joining a full
	// absolute path with an import path would double the path).
	var files []string
	for _, dir := range schemaDirs {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".proto") {
				rel, rerr := filepath.Rel(dir, p)
				if rerr != nil {
					return rerr
				}
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	if len(files) == 0 {
		return r, nil
	}
	descs, err := compiler.Compile(ctx, files...)
	if err != nil {
		return nil, fmt.Errorf("grpcproto: compile schemas: %w", err)
	}
	for _, fd := range descs {
		r.indexFile(fd)
	}
	return r, nil
}

func (r *Registry) indexFile(fd protoreflect.FileDescriptor) {
	sd := fd.Services()
	for i := 0; i < sd.Len(); i++ {
		svc := sd.Get(i)
		md := svc.Methods()
		for j := 0; j < md.Len(); j++ {
			m := md.Get(j)
			key := "/" + string(svc.FullName()) + "/" + string(m.Name())
			r.methods[key] = m
		}
	}
	// Register all message types in the file (recursively) so dynamic
	// unmarshalling can resolve nested/Any types.
	registerMessages(fd.Messages(), r.types)
	imps := fd.Imports()
	for i := 0; i < imps.Len(); i++ {
		if d := imps.Get(i).FileDescriptor; d != nil {
			r.indexFile(d)
		}
	}
}

func registerMessages(mds protoreflect.MessageDescriptors, types *protoregistry.Types) {
	for i := 0; i < mds.Len(); i++ {
		md := mds.Get(i)
		if err := types.RegisterMessage(dynamicpb.NewMessageType(md)); err != nil {
			if proto1Err(err) {
				continue
			}
		}
		registerMessages(md.Messages(), types)
	}
}

func proto1Err(err error) bool { return err != nil }

// HasMethod reports whether the registry knows the given full method name.
func (r *Registry) HasMethod(fullMethod string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.methods[fullMethod]
	return ok
}

// Report is the field-level inspection outcome.
type Report struct {
	ServiceName string               `json:"service_name"`
	MethodName  string               `json:"method_name"`
	Fields      []decision.GRPCField `json:"fields"`
	// Flat maps field names to stringified values for rule matching.
	Flat        map[string]string `json:"flat"`
	Malformed   bool              `json:"malformed"`
	KnownSchema bool              `json:"known_schema"`
}

// Inspect parses the body of one gRPC request against its schema.
// fullMethod is the HTTP/2 :path, e.g. /helloworld.Greeter/SayHello.
func (r *Registry) Inspect(fullMethod string, body []byte) Report {
	rep := Report{Flat: map[string]string{}}
	r.mu.RLock()
	m := r.methods[fullMethod]
	r.mu.RUnlock()
	if m == nil {
		rep.KnownSchema = false
		rep.Malformed = false
		rep.ServiceName = methodParts(fullMethod).svc
		rep.MethodName = methodParts(fullMethod).method
		return rep
	}
	rep.KnownSchema = true
	parts := methodParts(fullMethod)
	rep.ServiceName = parts.svc
	rep.MethodName = parts.method

	in := m.Input()
	msg := dynamicpb.NewMessage(in)
	data := stripGRPCFrame(body)
	opts := proto.UnmarshalOptions{Resolver: r.types}
	if err := opts.Unmarshal(data, msg.ProtoReflect().Interface()); err != nil {
		rep.Malformed = true
		return rep
	}
	walkMessage(msg, rep.Flat, &rep.Fields)
	sort.Slice(rep.Fields, func(i, j int) bool { return rep.Fields[i].FieldNumber < rep.Fields[j].FieldNumber })
	return rep
}

func walkMessage(msg protoreflect.Message, flat map[string]string, fields *[]decision.GRPCField) {
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		f := decision.GRPCField{
			FieldNumber: int(fd.Number()),
			Name:        string(fd.Name()),
			WireType:    int(fd.Kind()),
		}
		f.Value = valueToString(fd, v)
		if s, ok := f.Value.(string); ok {
			flat[string(fd.Name())] = s
		} else if fd.Kind() == protoreflect.MessageKind && v.Message().IsValid() {
			// Flatten nested message leaves so rules see field values at any
			// depth without an explicit path walk.
			v.Message().Range(func(nfd protoreflect.FieldDescriptor, nv protoreflect.Value) bool {
				if s, ok := valueToString(nfd, nv).(string); ok {
					flat[string(nfd.Name())] = s
				}
				return true
			})
		}
		*fields = append(*fields, f)
		return true
	})
}

func valueToString(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		if v.Message().IsValid() {
			out := map[string]any{}
			v.Message().Range(func(nfd protoreflect.FieldDescriptor, nv protoreflect.Value) bool {
				out[string(nfd.Name())] = valueToString(nfd, nv)
				return true
			})
			return out
		}
		return nil
	case protoreflect.EnumKind:
		return string(fd.Enum().Values().ByNumber(v.Enum()).Name())
	case protoreflect.BytesKind:
		return string(v.Bytes())
	default:
		if fd.IsList() {
			l := v.List()
			var items []any
			for i := 0; i < l.Len(); i++ {
				items = append(items, l.Get(i).String())
			}
			return items
		}
		return v.String()
	}
}

func stripGRPCFrame(body []byte) []byte {
	// gRPC length-prefixed message: 1 byte compression flag + 4 byte length.
	if len(body) >= 5 {
		l := int(body[1])<<24 | int(body[2])<<16 | int(body[3])<<8 | int(body[4])
		if (body[0] == 0 || body[0] == 1) && l >= 0 && l <= len(body)-5 {
			return body[5 : 5+l]
		}
	}
	return body
}

type mp struct{ svc, method string }

func methodParts(fullMethod string) mp {
	s := strings.TrimPrefix(fullMethod, "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return mp{svc: s[:i], method: s[i+1:]}
	}
	return mp{method: fullMethod}
}
