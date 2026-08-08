package grpcproto

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// schemaDir locates the checked-in .proto fixtures relative to this package.
func schemaDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "test", "grpc-fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry(context.Background(), []string{schemaDir(t)}, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func frame(t *testing.T, msg *dynamicpb.Message) []byte {
	t.Helper()
	payload, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 5+len(payload))
	out[0] = 0 // uncompressed
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func TestRegistryCompilesAndIndexes(t *testing.T) {
	reg := testRegistry(t)
	if !reg.HasMethod("/echov1.Echo/SayHello") {
		t.Fatal("SayHello not indexed")
	}
	if !reg.HasMethod("/echov1.Echo/Search") {
		t.Fatal("Search not indexed")
	}
	if reg.HasMethod("/nope.Foo/Bar") {
		t.Fatal("unknown method should not be indexed")
	}
}

func TestInspectParsesFields(t *testing.T) {
	reg := testRegistry(t)
	md := findMessage(t, reg, "echov1.HelloRequest")
	msg := dynamicpb.NewMessage(md)
	msg.Set(md.Fields().ByName("name"), protoreflect.ValueOfString("alice"))
	msg.Set(md.Fields().ByName("greeting"), protoreflect.ValueOfString("hello there"))

	rep := reg.Inspect("/echov1.Echo/SayHello", frame(t, msg))
	if rep.Malformed {
		t.Fatalf("malformed: %+v", rep)
	}
	if rep.ServiceName != "echov1.Echo" || rep.MethodName != "SayHello" {
		t.Fatalf("method = %s/%s", rep.ServiceName, rep.MethodName)
	}
	if rep.Flat["name"] != "alice" {
		t.Fatalf("flat name = %q", rep.Flat["name"])
	}
	if len(rep.Fields) != 2 {
		t.Fatalf("fields = %d", len(rep.Fields))
	}
}

func TestInspectMalformedPayload(t *testing.T) {
	reg := testRegistry(t)
	rep := reg.Inspect("/echov1.Echo/SayHello", []byte{0, 0, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0xff})
	if !rep.Malformed {
		t.Fatal("garbage payload should be marked malformed")
	}
}

func TestInspectUnknownMethod(t *testing.T) {
	reg := testRegistry(t)
	rep := reg.Inspect("/other.Thing/Do", []byte{})
	if rep.KnownSchema {
		t.Fatal("unknown method reported as known schema")
	}
	if rep.Malformed {
		t.Fatal("unknown method must not be 'malformed' — it simply has no schema")
	}
}

func TestInspectFlatContainsNested(t *testing.T) {
	reg := testRegistry(t)
	md := findMessage(t, reg, "echov1.SearchRequest")
	msg := dynamicpb.NewMessage(md)
	msg.Set(md.Fields().ByName("query"), protoreflect.ValueOfString("cats"))
	msg.Set(md.Fields().ByName("limit"), protoreflect.ValueOfInt32(10))
	meta := msg.Mutable(md.Fields().ByName("meta"))
	metaMsg := meta.Message()
	nested := findMessage(t, reg, "echov1.Nested")
	metaMsg.Set(nested.Fields().ByName("note"), protoreflect.ValueOfString("flagged"))

	rep := reg.Inspect("/echov1.Echo/Search", frame(t, msg))
	if rep.Malformed {
		t.Fatalf("malformed: %+v", rep)
	}
	if rep.Flat["query"] != "cats" {
		t.Fatalf("query = %q", rep.Flat["query"])
	}
	if rep.Flat["note"] != "flagged" {
		t.Fatalf("nested note = %q (flat=%+v)", rep.Flat["note"], rep.Flat)
	}
}

// findMessage locates a message descriptor by full name in the registry.
func findMessage(t *testing.T, reg *Registry, fullName string) protoreflect.MessageDescriptor {
	t.Helper()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	var found protoreflect.MessageDescriptor
	reg.types.RangeMessages(func(mt protoreflect.MessageType) bool {
		if string(mt.Descriptor().FullName()) == fullName {
			found = mt.Descriptor()
			return false
		}
		return true
	})
	if found == nil {
		t.Fatalf("message %s not found in registry", fullName)
	}
	return found
}
