package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Finding represents a simplified finding for notifications
type Finding struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	File   string `json:"file"`
}

// Event represents a notification event from watch mode
type Event struct {
	New      []Finding
	Resolved []Finding
	Total    int
	RepoPath string
}

// Notifier sends notifications about watch mode events
type Notifier interface {
	Notify(event Event) error
}

// SlackNotifier sends webhook notifications to Slack
type SlackNotifier struct {
	WebhookURL string
	client     *http.Client
}

// NewSlackNotifier creates a Slack webhook notifier
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		WebhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// slackMessage is the Slack webhook payload
type slackMessage struct {
	Text string `json:"text"`
}

// Notify sends a Slack message about new findings
func (s *SlackNotifier) Notify(event Event) error {
	if len(event.New) == 0 && len(event.Resolved) == 0 {
		return nil
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("*vaultspectre* — %d total findings", event.Total))
	if event.RepoPath != "" {
		buf.WriteString(fmt.Sprintf(" in `%s`", event.RepoPath))
	}
	buf.WriteString("\n")

	if len(event.New) > 0 {
		buf.WriteString(fmt.Sprintf("\n:warning: *%d new finding(s):*\n", len(event.New)))
		for _, f := range event.New {
			buf.WriteString(fmt.Sprintf("  • `[%s]` %s (%s)\n", f.Status, f.Path, f.File))
		}
	}

	if len(event.Resolved) > 0 {
		buf.WriteString(fmt.Sprintf("\n:white_check_mark: *%d resolved:*\n", len(event.Resolved)))
		for _, f := range event.Resolved {
			buf.WriteString(fmt.Sprintf("  • `[%s]` %s (%s)\n", f.Status, f.Path, f.File))
		}
	}

	msg := slackMessage{Text: buf.String()}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	resp, err := s.client.Post(s.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack webhook request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}
