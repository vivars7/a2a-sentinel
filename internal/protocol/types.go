// Package protocol defines A2A protocol types and request detection.
// All types follow the A2A RC v1.0 specification with camelCase JSON tags.
package protocol

import (
	"encoding/json"
)

// ── Agent Card Types ──

// AgentCard represents an A2A Agent Card per the A2A specification.
type AgentCard struct {
	Name                               string                       `json:"name"`
	Description                        string                       `json:"description,omitempty"`
	URL                                string                       `json:"url"`
	Version                            string                       `json:"version,omitempty"`
	DocumentationURL                   string                       `json:"documentationUrl,omitempty"`
	Provider                           *AgentProvider               `json:"provider,omitempty"`
	Capabilities                       *AgentCapabilities           `json:"capabilities,omitempty"`
	SecuritySchemes                    map[string]SecurityScheme    `json:"securitySchemes,omitempty"`
	Security                           []map[string][]string        `json:"security,omitempty"`
	Skills                             []AgentSkill                 `json:"skills,omitempty"`
	DefaultInputModes                  []string                     `json:"defaultInputModes,omitempty"`
	DefaultOutputModes                 []string                     `json:"defaultOutputModes,omitempty"`
	Interfaces                         *AgentInterfaces             `json:"interfaces,omitempty"`
	SupportsAuthenticatedExtendedCard  bool                         `json:"supportsAuthenticatedExtendedCard,omitempty"`
}

// AgentProvider identifies the organization providing the agent.
type AgentProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url,omitempty"`
}

// AgentCapabilities describes what features the agent supports.
type AgentCapabilities struct {
	Streaming              bool `json:"streaming,omitempty"`
	PushNotifications      bool `json:"pushNotifications,omitempty"`
	StateTransitionHistory bool `json:"stateTransitionHistory,omitempty"`
}

// AgentInterfaces lists protocol interfaces exposed by the agent.
type AgentInterfaces struct {
	JSONRPC string `json:"jsonrpc,omitempty"`
	GRPC    string `json:"grpc,omitempty"`
	REST    string `json:"rest,omitempty"`
}

// AgentSkill represents a skill that an agent can perform.
type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// SecurityScheme defines an authentication mechanism (OpenAPI-style).
type SecurityScheme struct {
	Type             string     `json:"type"`
	Description      string     `json:"description,omitempty"`
	Scheme           string     `json:"scheme,omitempty"`
	BearerFormat     string     `json:"bearerFormat,omitempty"`
	Flows            *OAuthFlows `json:"flows,omitempty"`
	In               string     `json:"in,omitempty"`
	Name             string     `json:"name,omitempty"`
	OpenIDConnectURL string     `json:"openIdConnectUrl,omitempty"`
}

// OAuthFlows describes the available OAuth 2.0 flows.
type OAuthFlows struct {
	Implicit          *OAuthFlow `json:"implicit,omitempty"`
	Password          *OAuthFlow `json:"password,omitempty"`
	ClientCredentials *OAuthFlow `json:"clientCredentials,omitempty"`
	AuthorizationCode *OAuthFlow `json:"authorizationCode,omitempty"`
}

// OAuthFlow describes a single OAuth 2.0 flow.
type OAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"`
}

// ── Task Types ──

// TaskState represents the state of an A2A task.
type TaskState string

const (
	// TaskStateSubmitted indicates the task has been submitted but not yet started.
	TaskStateSubmitted TaskState = "submitted"
	// TaskStateWorking indicates the task is currently being processed.
	TaskStateWorking TaskState = "working"
	// TaskStateInputRequired indicates the task needs additional input.
	TaskStateInputRequired TaskState = "input-required"
	// TaskStateCompleted indicates the task has finished successfully.
	TaskStateCompleted TaskState = "completed"
	// TaskStateCanceled indicates the task was canceled.
	TaskStateCanceled TaskState = "canceled"
	// TaskStateFailed indicates the task failed.
	TaskStateFailed TaskState = "failed"
	// TaskStateUnknown indicates the task state is unknown.
	TaskStateUnknown TaskState = "unknown"
)

// Task represents an A2A task.
type Task struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"sessionId,omitempty"`
	Status    TaskStatus             `json:"status"`
	History   []Message              `json:"history,omitempty"`
	Artifacts []Artifact             `json:"artifacts,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// TaskStatus represents the current status of a task.
type TaskStatus struct {
	State     TaskState `json:"state"`
	Message   *Message  `json:"message,omitempty"`
	Timestamp string    `json:"timestamp,omitempty"`
}

// ── Message Types ──

// Message represents an A2A message exchanged between agents.
type Message struct {
	Role      string                 `json:"role"`
	Parts     []Part                 `json:"parts"`
	MessageID string                 `json:"messageId,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Part represents a message part (text, file, or data).
// The Type field determines which other fields are populated.
type Part struct {
	Type     string                 `json:"type"`
	Text     string                 `json:"text,omitempty"`
	File     *FileContent           `json:"file,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FileContent represents file data in a FilePart.
type FileContent struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Bytes    string `json:"bytes,omitempty"`
	URI      string `json:"uri,omitempty"`
}

// Artifact represents a task artifact (output).
type Artifact struct {
	ArtifactID  string                 `json:"artifactId,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Parts       []Part                 `json:"parts"`
	Index       int                    `json:"index,omitempty"`
	Append      *bool                  `json:"append,omitempty"`
	LastChunk   *bool                  `json:"lastChunk,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ── Request Types ──

// SendMessageRequest is the payload for message/send and message/stream.
type SendMessageRequest struct {
	Message       Message                   `json:"message"`
	Configuration *SendMessageConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]interface{}    `json:"metadata,omitempty"`
}

// SendMessageConfiguration holds configuration for a send request.
type SendMessageConfiguration struct {
	AcceptedOutputModes []string                `json:"acceptedOutputModes,omitempty"`
	Blocking            *bool                   `json:"blocking,omitempty"`
	HistoryLength       *int                    `json:"historyLength,omitempty"`
	PushNotification    *PushNotificationConfig `json:"pushNotificationConfig,omitempty"`
}

// ── Push Notification Types ──

// PushNotificationConfig holds push notification settings.
type PushNotificationConfig struct {
	URL            string                              `json:"url"`
	Token          string                              `json:"token,omitempty"`
	Authentication *PushNotificationAuthenticationInfo `json:"authentication,omitempty"`
}

// PushNotificationAuthenticationInfo holds auth info for push callbacks.
type PushNotificationAuthenticationInfo struct {
	Schemes     []string `json:"schemes,omitempty"`
	Credentials string   `json:"credentials,omitempty"`
}

// ── SSE Event Types ──

// TaskStatusUpdateEvent is sent via SSE when a task's status changes.
type TaskStatusUpdateEvent struct {
	ID       string                 `json:"id"`
	Status   TaskStatus             `json:"status"`
	Final    bool                   `json:"final,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TaskArtifactUpdateEvent is sent via SSE when an artifact is updated.
type TaskArtifactUpdateEvent struct {
	ID       string                 `json:"id"`
	Artifact Artifact               `json:"artifact"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ── JSON-RPC Types ──

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}
