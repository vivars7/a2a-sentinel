package protocol

import (
	"net/http"
	"strings"
)

// MatchRESTPattern matches an HTTP request method and path against A2A REST URL patterns.
// Returns the A2A method name or empty string if no match.
func MatchRESTPattern(method string, path string) string {
	switch method {
	case http.MethodPost:
		return matchRESTPost(path)
	case http.MethodGet:
		return matchRESTGet(path)
	case http.MethodDelete:
		return matchRESTDelete(path)
	}

	return ""
}

// matchRESTPost matches POST request paths against A2A REST patterns.
func matchRESTPost(path string) string {
	// POST /message:send → message/send
	if path == "/message:send" {
		return "message/send"
	}

	// POST /message:stream → message/stream
	if path == "/message:stream" {
		return "message/stream"
	}

	// POST /tasks/{id}:cancel → tasks/cancel
	if strings.HasPrefix(path, "/tasks/") && strings.HasSuffix(path, ":cancel") {
		id := extractTaskID(path)
		if id != "" {
			return "tasks/cancel"
		}
	}

	// POST /tasks/{id}/pushNotifications → tasks/pushNotificationConfig/set
	if strings.HasPrefix(path, "/tasks/") && strings.HasSuffix(path, "/pushNotifications") {
		id := extractTaskIDBeforeSegment(path, "/pushNotifications")
		if id != "" {
			return "tasks/pushNotificationConfig/set"
		}
	}

	return ""
}

// matchRESTGet matches GET request paths against A2A REST patterns.
func matchRESTGet(path string) string {
	// GET /tasks → tasks/list
	if path == "/tasks" {
		return "tasks/list"
	}

	// GET /tasks/{id}:subscribe → tasks/subscribe
	if strings.HasPrefix(path, "/tasks/") && strings.HasSuffix(path, ":subscribe") {
		id := extractTaskID(path)
		if id != "" {
			return "tasks/subscribe"
		}
	}

	// GET /tasks/{id}/pushNotifications → tasks/pushNotificationConfig/get
	if strings.HasPrefix(path, "/tasks/") && strings.HasSuffix(path, "/pushNotifications") {
		id := extractTaskIDBeforeSegment(path, "/pushNotifications")
		if id != "" {
			return "tasks/pushNotificationConfig/get"
		}
	}

	// GET /tasks/{id} → tasks/get (must come after more specific patterns)
	if strings.HasPrefix(path, "/tasks/") {
		rest := path[len("/tasks/"):]
		if rest != "" && !strings.Contains(rest, "/") && !strings.Contains(rest, ":") {
			return "tasks/get"
		}
	}

	return ""
}

// matchRESTDelete matches DELETE request paths against A2A REST patterns.
func matchRESTDelete(path string) string {
	// DELETE /tasks/{id}/pushNotifications → tasks/pushNotificationConfig/delete
	if strings.HasPrefix(path, "/tasks/") && strings.HasSuffix(path, "/pushNotifications") {
		id := extractTaskIDBeforeSegment(path, "/pushNotifications")
		if id != "" {
			return "tasks/pushNotificationConfig/delete"
		}
	}

	return ""
}

// extractTaskID extracts the task ID from paths like /tasks/{id}:action.
// Returns the ID portion or empty string if invalid.
func extractTaskID(path string) string {
	// Remove /tasks/ prefix
	rest := path[len("/tasks/"):]

	// Find the colon separator for action
	colonIdx := strings.Index(rest, ":")
	if colonIdx <= 0 {
		return ""
	}

	return rest[:colonIdx]
}

// extractTaskIDBeforeSegment extracts the task ID from paths like /tasks/{id}/segment.
// Returns the ID portion or empty string if invalid.
func extractTaskIDBeforeSegment(path string, segment string) string {
	// Remove the segment suffix
	prefix := strings.TrimSuffix(path, segment)

	// Remove /tasks/ prefix
	if !strings.HasPrefix(prefix, "/tasks/") {
		return ""
	}
	id := prefix[len("/tasks/"):]

	if id == "" || strings.Contains(id, "/") {
		return ""
	}

	return id
}
