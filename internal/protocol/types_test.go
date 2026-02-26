package protocol

import (
	"encoding/json"
	"testing"
)

// ── TaskState Constants ──

func TestTaskStateConstants(t *testing.T) {
	tests := []struct {
		state TaskState
		want  string
	}{
		{TaskStateSubmitted, "submitted"},
		{TaskStateWorking, "working"},
		{TaskStateInputRequired, "input-required"},
		{TaskStateCompleted, "completed"},
		{TaskStateCanceled, "canceled"},
		{TaskStateFailed, "failed"},
		{TaskStateUnknown, "unknown"},
	}
	for _, tt := range tests {
		if string(tt.state) != tt.want {
			t.Errorf("TaskState %q != %q", tt.state, tt.want)
		}
	}
}

// ── Agent Card ──

func TestAgentCardUnmarshal(t *testing.T) {
	raw := `{
		"name": "Weather Agent",
		"description": "Provides weather information",
		"url": "https://weather-agent.example.com",
		"version": "1.0.0",
		"capabilities": {
			"streaming": true,
			"pushNotifications": false
		},
		"skills": [
			{
				"id": "get-weather",
				"name": "Get Weather",
				"description": "Get current weather for a location",
				"tags": ["weather", "forecast"],
				"inputModes": ["text"],
				"outputModes": ["text"]
			}
		],
		"securitySchemes": {
			"bearer": {
				"type": "http",
				"scheme": "bearer",
				"bearerFormat": "JWT"
			}
		},
		"defaultInputModes": ["text"],
		"defaultOutputModes": ["text"]
	}`

	var card AgentCard
	if err := json.Unmarshal([]byte(raw), &card); err != nil {
		t.Fatalf("unmarshal AgentCard: %v", err)
	}

	if card.Name != "Weather Agent" {
		t.Errorf("Name = %q, want %q", card.Name, "Weather Agent")
	}
	if card.Description != "Provides weather information" {
		t.Errorf("Description = %q", card.Description)
	}
	if card.URL != "https://weather-agent.example.com" {
		t.Errorf("URL = %q", card.URL)
	}
	if card.Version != "1.0.0" {
		t.Errorf("Version = %q", card.Version)
	}
	if card.Capabilities == nil {
		t.Fatal("Capabilities is nil")
	}
	if !card.Capabilities.Streaming {
		t.Error("Capabilities.Streaming should be true")
	}
	if card.Capabilities.PushNotifications {
		t.Error("Capabilities.PushNotifications should be false")
	}
	if len(card.Skills) != 1 {
		t.Fatalf("Skills len = %d, want 1", len(card.Skills))
	}
	skill := card.Skills[0]
	if skill.ID != "get-weather" {
		t.Errorf("Skill.ID = %q", skill.ID)
	}
	if skill.Name != "Get Weather" {
		t.Errorf("Skill.Name = %q", skill.Name)
	}
	if len(skill.Tags) != 2 || skill.Tags[0] != "weather" || skill.Tags[1] != "forecast" {
		t.Errorf("Skill.Tags = %v", skill.Tags)
	}
	if len(skill.InputModes) != 1 || skill.InputModes[0] != "text" {
		t.Errorf("Skill.InputModes = %v", skill.InputModes)
	}

	scheme, ok := card.SecuritySchemes["bearer"]
	if !ok {
		t.Fatal("SecuritySchemes missing 'bearer'")
	}
	if scheme.Type != "http" {
		t.Errorf("SecurityScheme.Type = %q", scheme.Type)
	}
	if scheme.Scheme != "bearer" {
		t.Errorf("SecurityScheme.Scheme = %q", scheme.Scheme)
	}
	if scheme.BearerFormat != "JWT" {
		t.Errorf("SecurityScheme.BearerFormat = %q", scheme.BearerFormat)
	}

	if len(card.DefaultInputModes) != 1 || card.DefaultInputModes[0] != "text" {
		t.Errorf("DefaultInputModes = %v", card.DefaultInputModes)
	}
	if len(card.DefaultOutputModes) != 1 || card.DefaultOutputModes[0] != "text" {
		t.Errorf("DefaultOutputModes = %v", card.DefaultOutputModes)
	}
}

func TestAgentCardRoundTrip(t *testing.T) {
	original := AgentCard{
		Name:    "Test Agent",
		URL:     "https://test.example.com",
		Version: "2.0.0",
		Provider: &AgentProvider{
			Organization: "TestCorp",
			URL:          "https://testcorp.com",
		},
		Capabilities: &AgentCapabilities{
			Streaming:              true,
			PushNotifications:      true,
			StateTransitionHistory: true,
		},
		Skills: []AgentSkill{
			{
				ID:          "skill-1",
				Name:        "Skill One",
				Description: "First skill",
				Tags:        []string{"tag1"},
				InputModes:  []string{"text"},
				OutputModes: []string{"text", "image"},
			},
		},
		SecuritySchemes: map[string]SecurityScheme{
			"oauth2": {
				Type: "oauth2",
				Flows: &OAuthFlows{
					AuthorizationCode: &OAuthFlow{
						AuthorizationURL: "https://auth.example.com/authorize",
						TokenURL:         "https://auth.example.com/token",
						Scopes: map[string]string{
							"read":  "Read access",
							"write": "Write access",
						},
					},
				},
			},
		},
		Security: []map[string][]string{
			{"oauth2": {"read", "write"}},
		},
		DefaultInputModes:  []string{"text"},
		DefaultOutputModes: []string{"text"},
		Interfaces: &AgentInterfaces{
			JSONRPC: "/jsonrpc",
			REST:    "/api",
		},
		SupportsAuthenticatedExtendedCard: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AgentCard
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != original.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, original.Name)
	}
	if decoded.Provider == nil || decoded.Provider.Organization != "TestCorp" {
		t.Error("Provider round-trip failed")
	}
	if decoded.Interfaces == nil || decoded.Interfaces.JSONRPC != "/jsonrpc" {
		t.Error("Interfaces round-trip failed")
	}
	if !decoded.SupportsAuthenticatedExtendedCard {
		t.Error("SupportsAuthenticatedExtendedCard round-trip failed")
	}
	if decoded.SecuritySchemes["oauth2"].Flows == nil {
		t.Fatal("OAuth flows round-trip failed")
	}
	flow := decoded.SecuritySchemes["oauth2"].Flows.AuthorizationCode
	if flow == nil {
		t.Fatal("AuthorizationCode flow is nil")
	}
	if flow.AuthorizationURL != "https://auth.example.com/authorize" {
		t.Errorf("AuthorizationURL = %q", flow.AuthorizationURL)
	}
	if len(flow.Scopes) != 2 {
		t.Errorf("Scopes len = %d", len(flow.Scopes))
	}
}

// ── Task ──

func TestTaskRoundTrip(t *testing.T) {
	boolTrue := true
	task := Task{
		ID:        "task-123",
		SessionID: "session-456",
		Status: TaskStatus{
			State: TaskStateWorking,
			Message: &Message{
				Role: "agent",
				Parts: []Part{
					{Type: "text", Text: "Processing..."},
				},
			},
			Timestamp: "2025-01-01T00:00:00Z",
		},
		History: []Message{
			{
				Role:      "user",
				MessageID: "msg-1",
				Parts:     []Part{{Type: "text", Text: "Hello"}},
			},
		},
		Artifacts: []Artifact{
			{
				ArtifactID: "art-1",
				Name:       "result",
				Parts:      []Part{{Type: "text", Text: "Result data"}},
				Index:      0,
				LastChunk:  &boolTrue,
			},
		},
		Metadata: map[string]interface{}{
			"priority": "high",
		},
	}

	data, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal Task: %v", err)
	}

	var decoded Task
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal Task: %v", err)
	}

	if decoded.ID != "task-123" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.SessionID != "session-456" {
		t.Errorf("SessionID = %q", decoded.SessionID)
	}
	if decoded.Status.State != TaskStateWorking {
		t.Errorf("Status.State = %q", decoded.Status.State)
	}
	if decoded.Status.Timestamp != "2025-01-01T00:00:00Z" {
		t.Errorf("Status.Timestamp = %q", decoded.Status.Timestamp)
	}
	if decoded.Status.Message == nil || decoded.Status.Message.Role != "agent" {
		t.Error("Status.Message round-trip failed")
	}
	if len(decoded.History) != 1 || decoded.History[0].MessageID != "msg-1" {
		t.Error("History round-trip failed")
	}
	if len(decoded.Artifacts) != 1 {
		t.Fatal("Artifacts round-trip failed")
	}
	art := decoded.Artifacts[0]
	if art.ArtifactID != "art-1" {
		t.Errorf("ArtifactID = %q", art.ArtifactID)
	}
	if art.LastChunk == nil || !*art.LastChunk {
		t.Error("LastChunk round-trip failed")
	}
}

// ── Message ──

func TestMessageRoundTrip(t *testing.T) {
	msg := Message{
		Role:      "user",
		MessageID: "msg-42",
		Parts: []Part{
			{Type: "text", Text: "What is the weather in Tokyo?"},
		},
		Metadata: map[string]interface{}{
			"source": "cli",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Role != "user" {
		t.Errorf("Role = %q", decoded.Role)
	}
	if decoded.MessageID != "msg-42" {
		t.Errorf("MessageID = %q", decoded.MessageID)
	}
	if len(decoded.Parts) != 1 || decoded.Parts[0].Type != "text" {
		t.Error("Parts round-trip failed")
	}
	if decoded.Parts[0].Text != "What is the weather in Tokyo?" {
		t.Errorf("Parts[0].Text = %q", decoded.Parts[0].Text)
	}
}

// ── Part Types ──

func TestPartTextMarshal(t *testing.T) {
	p := Part{Type: "text", Text: "hello world"}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Part
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != "text" {
		t.Errorf("Type = %q", decoded.Type)
	}
	if decoded.Text != "hello world" {
		t.Errorf("Text = %q", decoded.Text)
	}
	if decoded.File != nil {
		t.Error("File should be nil for text part")
	}
}

func TestPartFileMarshal(t *testing.T) {
	p := Part{
		Type: "file",
		File: &FileContent{
			Name:     "report.pdf",
			MimeType: "application/pdf",
			URI:      "https://example.com/report.pdf",
		},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Part
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != "file" {
		t.Errorf("Type = %q", decoded.Type)
	}
	if decoded.File == nil {
		t.Fatal("File is nil")
	}
	if decoded.File.Name != "report.pdf" {
		t.Errorf("File.Name = %q", decoded.File.Name)
	}
	if decoded.File.MimeType != "application/pdf" {
		t.Errorf("File.MimeType = %q", decoded.File.MimeType)
	}
	if decoded.File.URI != "https://example.com/report.pdf" {
		t.Errorf("File.URI = %q", decoded.File.URI)
	}
}

func TestPartFileWithBytes(t *testing.T) {
	p := Part{
		Type: "file",
		File: &FileContent{
			Name:     "data.txt",
			MimeType: "text/plain",
			Bytes:    "aGVsbG8gd29ybGQ=", // base64 "hello world"
		},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Part
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.File.Bytes != "aGVsbG8gd29ybGQ=" {
		t.Errorf("File.Bytes = %q", decoded.File.Bytes)
	}
	if decoded.File.URI != "" {
		t.Error("File.URI should be empty when bytes is set")
	}
}

func TestPartDataMarshal(t *testing.T) {
	p := Part{
		Type: "data",
		Data: map[string]interface{}{
			"temperature": 25.5,
			"unit":        "celsius",
		},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Part
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != "data" {
		t.Errorf("Type = %q", decoded.Type)
	}
	if decoded.Data == nil {
		t.Fatal("Data is nil")
	}
	if decoded.Data["unit"] != "celsius" {
		t.Errorf("Data[unit] = %v", decoded.Data["unit"])
	}
}

func TestPartWithMetadata(t *testing.T) {
	p := Part{
		Type: "text",
		Text: "annotated",
		Metadata: map[string]interface{}{
			"confidence": 0.95,
		},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Part
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if decoded.Metadata["confidence"] != 0.95 {
		t.Errorf("Metadata[confidence] = %v", decoded.Metadata["confidence"])
	}
}

// ── JSON-RPC ──

func TestJSONRPCRequestUnmarshal(t *testing.T) {
	raw := `{
		"jsonrpc": "2.0",
		"method": "message/send",
		"id": "req-1",
		"params": {
			"message": {
				"role": "user",
				"parts": [{"type": "text", "text": "What is the weather in Tokyo?"}],
				"messageId": "msg-1"
			}
		}
	}`

	var req JSONRPCRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if req.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q", req.JSONRPC)
	}
	if req.Method != "message/send" {
		t.Errorf("Method = %q", req.Method)
	}
	if req.ID != "req-1" {
		t.Errorf("ID = %v", req.ID)
	}
	if req.Params == nil {
		t.Fatal("Params is nil")
	}

	// Parse params into SendMessageRequest
	var params SendMessageRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if params.Message.Role != "user" {
		t.Errorf("Message.Role = %q", params.Message.Role)
	}
	if len(params.Message.Parts) != 1 {
		t.Fatalf("Message.Parts len = %d", len(params.Message.Parts))
	}
	if params.Message.Parts[0].Text != "What is the weather in Tokyo?" {
		t.Errorf("Message.Parts[0].Text = %q", params.Message.Parts[0].Text)
	}
	if params.Message.MessageID != "msg-1" {
		t.Errorf("Message.MessageID = %q", params.Message.MessageID)
	}
}

func TestJSONRPCRequestRoundTrip(t *testing.T) {
	params, _ := json.Marshal(SendMessageRequest{
		Message: Message{
			Role:      "user",
			Parts:     []Part{{Type: "text", Text: "Hello"}},
			MessageID: "msg-99",
		},
	})

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "message/send",
		Params:  params,
		ID:      "req-42",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded JSONRPCRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q", decoded.JSONRPC)
	}
	if decoded.Method != "message/send" {
		t.Errorf("Method = %q", decoded.Method)
	}
}

func TestJSONRPCResponseSuccess(t *testing.T) {
	taskResult, _ := json.Marshal(Task{
		ID: "task-1",
		Status: TaskStatus{
			State: TaskStateCompleted,
		},
	})

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  taskResult,
		ID:      "req-1",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded JSONRPCResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q", decoded.JSONRPC)
	}
	if decoded.Error != nil {
		t.Error("Error should be nil for success response")
	}
	if decoded.Result == nil {
		t.Fatal("Result is nil")
	}

	var task Task
	if err := json.Unmarshal(decoded.Result, &task); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if task.ID != "task-1" {
		t.Errorf("task.ID = %q", task.ID)
	}
	if task.Status.State != TaskStateCompleted {
		t.Errorf("task.Status.State = %q", task.Status.State)
	}
}

func TestJSONRPCResponseError(t *testing.T) {
	errData, _ := json.Marshal(map[string]string{
		"hint": "Invalid method name",
	})

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &JSONRPCError{
			Code:    -32601,
			Message: "Method not found",
			Data:    errData,
		},
		ID: "req-2",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded JSONRPCResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Error == nil {
		t.Fatal("Error is nil")
	}
	if decoded.Error.Code != -32601 {
		t.Errorf("Error.Code = %d", decoded.Error.Code)
	}
	if decoded.Error.Message != "Method not found" {
		t.Errorf("Error.Message = %q", decoded.Error.Message)
	}
	if decoded.Result != nil {
		t.Error("Result should be nil for error response")
	}
}

func TestJSONRPCRequestNumericID(t *testing.T) {
	raw := `{"jsonrpc":"2.0","method":"tasks/get","id":42,"params":{"id":"task-1"}}`

	var req JSONRPCRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// JSON numbers unmarshal as float64 for interface{}
	if id, ok := req.ID.(float64); !ok || id != 42 {
		t.Errorf("ID = %v (type %T)", req.ID, req.ID)
	}
}

func TestJSONRPCRequestNullID(t *testing.T) {
	raw := `{"jsonrpc":"2.0","method":"message/send","id":null}`

	var req JSONRPCRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if req.ID != nil {
		t.Errorf("ID = %v, want nil", req.ID)
	}
}

// ── SSE Events ──

func TestTaskStatusUpdateEventMarshal(t *testing.T) {
	evt := TaskStatusUpdateEvent{
		ID: "task-1",
		Status: TaskStatus{
			State:     TaskStateWorking,
			Timestamp: "2025-01-01T00:00:00Z",
		},
		Final: false,
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TaskStatusUpdateEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != "task-1" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.Status.State != TaskStateWorking {
		t.Errorf("Status.State = %q", decoded.Status.State)
	}
}

func TestTaskArtifactUpdateEventMarshal(t *testing.T) {
	boolFalse := false
	evt := TaskArtifactUpdateEvent{
		ID: "task-1",
		Artifact: Artifact{
			ArtifactID: "art-1",
			Name:       "output",
			Parts:      []Part{{Type: "text", Text: "chunk 1"}},
			Index:      0,
			Append:     &boolFalse,
		},
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TaskArtifactUpdateEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != "task-1" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.Artifact.ArtifactID != "art-1" {
		t.Errorf("Artifact.ArtifactID = %q", decoded.Artifact.ArtifactID)
	}
	if decoded.Artifact.Append == nil || *decoded.Artifact.Append != false {
		t.Error("Artifact.Append round-trip failed")
	}
}

// ── SendMessageRequest ──

func TestSendMessageRequestRoundTrip(t *testing.T) {
	boolTrue := true
	histLen := 10

	req := SendMessageRequest{
		Message: Message{
			Role:      "user",
			Parts:     []Part{{Type: "text", Text: "Hello agent"}},
			MessageID: "msg-1",
		},
		Configuration: &SendMessageConfiguration{
			AcceptedOutputModes: []string{"text", "image"},
			Blocking:            &boolTrue,
			HistoryLength:       &histLen,
			PushNotification: &PushNotificationConfig{
				URL:   "https://callback.example.com/notify",
				Token: "cb-token-123",
				Authentication: &PushNotificationAuthenticationInfo{
					Schemes:     []string{"bearer"},
					Credentials: "secret-cred",
				},
			},
		},
		Metadata: map[string]interface{}{
			"requestSource": "test",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SendMessageRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Message.Role != "user" {
		t.Errorf("Message.Role = %q", decoded.Message.Role)
	}
	if decoded.Configuration == nil {
		t.Fatal("Configuration is nil")
	}
	if !*decoded.Configuration.Blocking {
		t.Error("Blocking should be true")
	}
	if *decoded.Configuration.HistoryLength != 10 {
		t.Errorf("HistoryLength = %d", *decoded.Configuration.HistoryLength)
	}
	if len(decoded.Configuration.AcceptedOutputModes) != 2 {
		t.Errorf("AcceptedOutputModes len = %d", len(decoded.Configuration.AcceptedOutputModes))
	}
	pn := decoded.Configuration.PushNotification
	if pn == nil {
		t.Fatal("PushNotification is nil")
	}
	if pn.URL != "https://callback.example.com/notify" {
		t.Errorf("PushNotification.URL = %q", pn.URL)
	}
	if pn.Token != "cb-token-123" {
		t.Errorf("PushNotification.Token = %q", pn.Token)
	}
	if pn.Authentication == nil {
		t.Fatal("PushNotification.Authentication is nil")
	}
	if len(pn.Authentication.Schemes) != 1 || pn.Authentication.Schemes[0] != "bearer" {
		t.Errorf("Authentication.Schemes = %v", pn.Authentication.Schemes)
	}
}

// ── Omitted Fields ──

func TestOmitEmptyFields(t *testing.T) {
	// Minimal AgentCard: only required fields
	card := AgentCard{
		Name: "Minimal",
		URL:  "https://example.com",
	}

	data, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// These fields should be omitted
	omitted := []string{
		"description", "version", "documentationUrl", "provider",
		"capabilities", "securitySchemes", "security", "skills",
		"defaultInputModes", "defaultOutputModes", "interfaces",
	}
	for _, field := range omitted {
		if _, exists := raw[field]; exists {
			t.Errorf("field %q should be omitted when empty", field)
		}
	}

	// Required fields should be present
	if _, exists := raw["name"]; !exists {
		t.Error("field 'name' should be present")
	}
	if _, exists := raw["url"]; !exists {
		t.Error("field 'url' should be present")
	}
}

// ── Full A2A JSON-RPC roundtrip ──

func TestFullJSONRPCMessageSendRoundTrip(t *testing.T) {
	// Simulate: client sends message/send → server responds with Task
	requestJSON := `{
		"jsonrpc": "2.0",
		"method": "message/send",
		"id": "req-100",
		"params": {
			"message": {
				"role": "user",
				"parts": [
					{"type": "text", "text": "Tell me about Go"},
					{"type": "data", "data": {"lang": "en"}}
				],
				"messageId": "msg-100"
			},
			"configuration": {
				"acceptedOutputModes": ["text"],
				"blocking": true
			}
		}
	}`

	// Parse request
	var req JSONRPCRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	var params SendMessageRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}

	if len(params.Message.Parts) != 2 {
		t.Fatalf("parts len = %d, want 2", len(params.Message.Parts))
	}
	if params.Message.Parts[0].Type != "text" {
		t.Errorf("parts[0].Type = %q", params.Message.Parts[0].Type)
	}
	if params.Message.Parts[1].Type != "data" {
		t.Errorf("parts[1].Type = %q", params.Message.Parts[1].Type)
	}
	if params.Message.Parts[1].Data["lang"] != "en" {
		t.Errorf("parts[1].Data[lang] = %v", params.Message.Parts[1].Data["lang"])
	}

	// Build response
	taskResult, _ := json.Marshal(Task{
		ID: "task-200",
		Status: TaskStatus{
			State:     TaskStateCompleted,
			Timestamp: "2025-06-01T12:00:00Z",
		},
		Artifacts: []Artifact{
			{
				ArtifactID: "art-1",
				Parts:      []Part{{Type: "text", Text: "Go is a programming language."}},
			},
		},
	})

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  taskResult,
		ID:      req.ID,
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var decodedResp JSONRPCResponse
	if err := json.Unmarshal(respData, &decodedResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	var task Task
	if err := json.Unmarshal(decodedResp.Result, &task); err != nil {
		t.Fatalf("unmarshal task: %v", err)
	}

	if task.ID != "task-200" {
		t.Errorf("task.ID = %q", task.ID)
	}
	if task.Status.State != TaskStateCompleted {
		t.Errorf("task.Status.State = %q", task.Status.State)
	}
	if len(task.Artifacts) != 1 {
		t.Fatalf("artifacts len = %d", len(task.Artifacts))
	}
	if task.Artifacts[0].Parts[0].Text != "Go is a programming language." {
		t.Errorf("artifact text = %q", task.Artifacts[0].Parts[0].Text)
	}
}
