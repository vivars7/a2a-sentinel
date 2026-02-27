// Package grpc implements the gRPC binding for the A2A protocol gateway.
// It translates between gRPC proto messages and internal protocol types,
// and forwards requests to backend agents via the existing HTTP proxy.
package grpc

import (
	"encoding/json"
	"fmt"

	a2av1 "github.com/vivars7/a2a-sentinel/gen/a2a/v1"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
	"google.golang.org/protobuf/types/known/structpb"
)

// ── gRPC → Internal (request translation) ──

// sendMessageRequestToInternal converts a gRPC SendMessageRequest to the internal type.
func sendMessageRequestToInternal(req *a2av1.SendMessageRequest) (*protocol.SendMessageRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}

	internal := &protocol.SendMessageRequest{
		Message: messageToInternal(req.GetMessage()),
	}

	if cfg := req.GetConfiguration(); cfg != nil {
		internal.Configuration = &protocol.SendMessageConfiguration{
			AcceptedOutputModes: cfg.GetAcceptedOutputModes(),
		}
		if cfg.Blocking != nil {
			b := cfg.GetBlocking()
			internal.Configuration.Blocking = &b
		}
		if cfg.HistoryLength != nil {
			hl := int(cfg.GetHistoryLength())
			internal.Configuration.HistoryLength = &hl
		}
		if pnc := cfg.GetPushNotificationConfig(); pnc != nil {
			internal.Configuration.PushNotification = pushNotifConfigToInternal(pnc)
		}
	}

	if req.GetMetadata() != nil {
		internal.Metadata = structToMap(req.GetMetadata())
	}

	return internal, nil
}

// messageToInternal converts a proto Message to the internal type.
func messageToInternal(msg *a2av1.Message) protocol.Message {
	if msg == nil {
		return protocol.Message{}
	}

	m := protocol.Message{
		Role:      msg.GetRole(),
		MessageID: msg.GetMessageId(),
	}

	for _, p := range msg.GetParts() {
		m.Parts = append(m.Parts, partToInternal(p))
	}

	if msg.GetMetadata() != nil {
		m.Metadata = structToMap(msg.GetMetadata())
	}

	return m
}

// partToInternal converts a proto Part to the internal type.
func partToInternal(p *a2av1.Part) protocol.Part {
	if p == nil {
		return protocol.Part{}
	}

	part := protocol.Part{
		Type: p.GetType(),
		Text: p.GetText(),
	}

	if f := p.GetFile(); f != nil {
		part.File = &protocol.FileContent{
			Name:     f.GetName(),
			MimeType: f.GetMimeType(),
			Bytes:    f.GetBytes(),
			URI:      f.GetUri(),
		}
	}

	if p.GetData() != nil {
		part.Data = structToMap(p.GetData())
	}
	if p.GetMetadata() != nil {
		part.Metadata = structToMap(p.GetMetadata())
	}

	return part
}

// pushNotifConfigToInternal converts a proto PushNotificationConfig to the internal type.
func pushNotifConfigToInternal(pnc *a2av1.PushNotificationConfig) *protocol.PushNotificationConfig {
	if pnc == nil {
		return nil
	}
	cfg := &protocol.PushNotificationConfig{
		URL:   pnc.GetUrl(),
		Token: pnc.GetToken(),
	}
	if auth := pnc.GetAuthentication(); auth != nil {
		cfg.Authentication = &protocol.PushNotificationAuthenticationInfo{
			Schemes:     auth.GetSchemes(),
			Credentials: auth.GetCredentials(),
		}
	}
	return cfg
}

// ── Internal → gRPC (response translation) ──

// taskToProto converts an internal Task to the proto type.
func taskToProto(t *protocol.Task) *a2av1.Task {
	if t == nil {
		return nil
	}

	task := &a2av1.Task{
		Id:        t.ID,
		SessionId: t.SessionID,
		Status:    taskStatusToProto(&t.Status),
	}

	for _, msg := range t.History {
		task.History = append(task.History, messageToProto(&msg))
	}
	for _, art := range t.Artifacts {
		task.Artifacts = append(task.Artifacts, artifactToProto(&art))
	}
	if t.Metadata != nil {
		task.Metadata = mapToStruct(t.Metadata)
	}

	return task
}

// taskStatusToProto converts an internal TaskStatus to the proto type.
func taskStatusToProto(s *protocol.TaskStatus) *a2av1.TaskStatus {
	if s == nil {
		return nil
	}
	ts := &a2av1.TaskStatus{
		State:     string(s.State),
		Timestamp: s.Timestamp,
	}
	if s.Message != nil {
		ts.Message = messageToProto(s.Message)
	}
	return ts
}

// messageToProto converts an internal Message to the proto type.
func messageToProto(m *protocol.Message) *a2av1.Message {
	if m == nil {
		return nil
	}
	msg := &a2av1.Message{
		Role:      m.Role,
		MessageId: m.MessageID,
	}
	for _, p := range m.Parts {
		msg.Parts = append(msg.Parts, partToProto(&p))
	}
	if m.Metadata != nil {
		msg.Metadata = mapToStruct(m.Metadata)
	}
	return msg
}

// partToProto converts an internal Part to the proto type.
func partToProto(p *protocol.Part) *a2av1.Part {
	if p == nil {
		return nil
	}
	part := &a2av1.Part{
		Type: p.Type,
		Text: p.Text,
	}
	if p.File != nil {
		part.File = &a2av1.FileContent{
			Name:     p.File.Name,
			MimeType: p.File.MimeType,
			Bytes:    p.File.Bytes,
			Uri:      p.File.URI,
		}
	}
	if p.Data != nil {
		part.Data = mapToStruct(p.Data)
	}
	if p.Metadata != nil {
		part.Metadata = mapToStruct(p.Metadata)
	}
	return part
}

// artifactToProto converts an internal Artifact to the proto type.
func artifactToProto(a *protocol.Artifact) *a2av1.Artifact {
	if a == nil {
		return nil
	}
	art := &a2av1.Artifact{
		ArtifactId:  a.ArtifactID,
		Name:        a.Name,
		Description: a.Description,
		Index:       int32(a.Index),
	}
	if a.Append != nil {
		art.Append = a.Append
	}
	if a.LastChunk != nil {
		art.LastChunk = a.LastChunk
	}
	for _, p := range a.Parts {
		art.Parts = append(art.Parts, partToProto(&p))
	}
	if a.Metadata != nil {
		art.Metadata = mapToStruct(a.Metadata)
	}
	return art
}

// pushNotifConfigToProto converts an internal PushNotificationConfig to the proto type.
func pushNotifConfigToProto(cfg *protocol.PushNotificationConfig) *a2av1.PushNotificationConfig {
	if cfg == nil {
		return nil
	}
	pnc := &a2av1.PushNotificationConfig{
		Url:   cfg.URL,
		Token: cfg.Token,
	}
	if cfg.Authentication != nil {
		pnc.Authentication = &a2av1.PushNotificationAuthenticationInfo{
			Schemes:     cfg.Authentication.Schemes,
			Credentials: cfg.Authentication.Credentials,
		}
	}
	return pnc
}

// taskStatusUpdateEventToProto converts an internal TaskStatusUpdateEvent to the proto type.
func taskStatusUpdateEventToProto(e *protocol.TaskStatusUpdateEvent) *a2av1.TaskStatusUpdateEvent {
	if e == nil {
		return nil
	}
	evt := &a2av1.TaskStatusUpdateEvent{
		Id:     e.ID,
		Status: taskStatusToProto(&e.Status),
		Final:  e.Final,
	}
	if e.Metadata != nil {
		evt.Metadata = mapToStruct(e.Metadata)
	}
	return evt
}

// taskArtifactUpdateEventToProto converts an internal TaskArtifactUpdateEvent to the proto type.
func taskArtifactUpdateEventToProto(e *protocol.TaskArtifactUpdateEvent) *a2av1.TaskArtifactUpdateEvent {
	if e == nil {
		return nil
	}
	evt := &a2av1.TaskArtifactUpdateEvent{
		Id:       e.ID,
		Artifact: artifactToProto(&e.Artifact),
	}
	if e.Metadata != nil {
		evt.Metadata = mapToStruct(e.Metadata)
	}
	return evt
}

// ── JSON-RPC envelope helpers ──

// wrapJSONRPC wraps parameters into a JSON-RPC 2.0 request envelope.
func wrapJSONRPC(method string, params interface{}, id interface{}) ([]byte, error) {
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshaling params: %w", err)
	}
	req := protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  paramsJSON,
		ID:      id,
	}
	return json.Marshal(req)
}

// unwrapJSONRPCResult extracts the result from a JSON-RPC 2.0 response body.
func unwrapJSONRPCResult(body []byte) (json.RawMessage, error) {
	var resp protocol.JSONRPCResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing JSON-RPC response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result, nil
}

// ── structpb conversion helpers ──

// structToMap converts a protobuf Struct to a Go map.
func structToMap(s *structpb.Struct) map[string]interface{} {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// mapToStruct converts a Go map to a protobuf Struct.
// Returns nil if the map is nil or conversion fails.
func mapToStruct(m map[string]interface{}) *structpb.Struct {
	if m == nil {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}

// ── A2A method mapping ──

// grpcMethodToA2A maps gRPC full method names to A2A JSON-RPC method names.
var grpcMethodToA2A = map[string]string{
	a2av1.A2AService_SendMessage_FullMethodName:               "message/send",
	a2av1.A2AService_StreamMessage_FullMethodName:             "message/stream",
	a2av1.A2AService_GetTask_FullMethodName:                   "tasks/get",
	a2av1.A2AService_CancelTask_FullMethodName:                "tasks/cancel",
	a2av1.A2AService_SetPushNotificationConfig_FullMethodName: "tasks/pushNotificationConfig/set",
	a2av1.A2AService_GetPushNotificationConfig_FullMethodName: "tasks/pushNotificationConfig/get",
}
