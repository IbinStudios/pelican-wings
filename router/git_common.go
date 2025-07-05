package router

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"net/http"
	"time"

	"github.com/pelican-dev/wings/server"
)

// GitRepository represents a single git repository configuration
type GitRepository struct {
	CleanName      string `json:"clean_name"`
	GitRepo        string `json:"git_repo"`
	Branch         string `json:"branch"`
	Path           string `json:"path"`
	GitHubTokenKey string `json:"github_token_key,omitempty"`
}

// MissingTokenError represents an error when a repository requires a token that's not available
type MissingTokenError struct {
	Repository GitRepository
	Message    string
}

func (e *MissingTokenError) Error() string {
	return e.Message
}

// GitTokenManager handles token storage in .git folder
type GitTokenManager struct {
	server *server.Server
}

// NewGitTokenManager creates a new token manager
func NewGitTokenManager(s *server.Server) *GitTokenManager {
	return &GitTokenManager{server: s}
}

// getTokensFilePath returns path to the tokens file in .git folder
func (tm *GitTokenManager) getTokensFilePath() string {
	basePath := tm.server.Filesystem().Path()
	return filepath.Join(basePath, ".git", "tokens")
}

// StoreToken stores a token with the given key
func (tm *GitTokenManager) StoreToken(key, token string) error {
	tokensFile := tm.getTokensFilePath()

	// Ensure .git directory exists
	gitDir := filepath.Dir(tokensFile)
	if err := os.MkdirAll(gitDir, 0700); err != nil {
		return fmt.Errorf("failed to create .git directory: %w", err)
	}

	// Load existing tokens
	tokens, err := tm.loadTokens()
	if err != nil {
		tokens = make(map[string]string)
	}

	// Update the token
	tokens[key] = token

	// Save tokens back to file
	return tm.saveTokens(tokens)
}

// GetToken retrieves a token by key
func (tm *GitTokenManager) GetToken(key string) (string, error) {
	tokens, err := tm.loadTokens()
	if err != nil {
		return "", err
	}

	token, exists := tokens[key]
	if !exists {
		return "", fmt.Errorf("token not found for key: %s", key)
	}

	return token, nil
}

// loadTokens loads tokens from the .git/tokens file
func (tm *GitTokenManager) loadTokens() (map[string]string, error) {
	tokensFile := tm.getTokensFilePath()

	if _, err := os.Stat(tokensFile); os.IsNotExist(err) {
		return make(map[string]string), nil
	}

	file, err := os.Open(tokensFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open tokens file: %w", err)
	}
	defer file.Close()

	tokens := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			tokens[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading tokens file: %w", err)
	}

	return tokens, nil
}

// saveTokens saves tokens to the .git/tokens file
func (tm *GitTokenManager) saveTokens(tokens map[string]string) error {
	tokensFile := tm.getTokensFilePath()

	file, err := os.Create(tokensFile)
	if err != nil {
		return fmt.Errorf("failed to create tokens file: %w", err)
	}
	defer file.Close()

	// Write header comment
	_, err = file.WriteString("# GitHub tokens for repositories\n")
	if err != nil {
		return err
	}
	_, err = file.WriteString("# This file is automatically managed by the panel\n")
	if err != nil {
		return err
	}
	_, err = file.WriteString("# Format: TOKEN_KEY=github_token_value\n\n")
	if err != nil {
		return err
	}

	// Write tokens
	for key, token := range tokens {
		_, err = file.WriteString(fmt.Sprintf("%s=%s\n", key, token))
		if err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	// Set restrictive permissions
	if err := os.Chmod(tokensFile, 0600); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}

// sanitizeGitURL removes tokens from URLs for logging
func sanitizeGitURL(url string) string {
	// Remove tokens from HTTPS URLs: https://token@github.com/user/repo.git -> https://github.com/user/repo.git
	re := regexp.MustCompile(`https://[^@]+@github\.com/`)
	return re.ReplaceAllString(url, "https://github.com/")
}

// DeleteToken removes a token by key
func (tm *GitTokenManager) DeleteToken(key string) error {
	tokens, err := tm.loadTokens()
	if err != nil {
		return err
	}

	delete(tokens, key)
	return tm.saveTokens(tokens)
}

// ValidateToken checks if a GitHub token is still valid
func (tm *GitTokenManager) ValidateToken(token string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "Wings-Git-Manager")
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()
	
	switch resp.StatusCode {
	case 200:
		return nil
	case 401:
		return fmt.Errorf("token is invalid or expired")
	case 403:
		// Check if it's a rate limit or token issue
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return fmt.Errorf("rate limit exceeded")
		}
		return fmt.Errorf("token lacks required permissions")
	default:
		return fmt.Errorf("unexpected response: %d", resp.StatusCode)
	}
}

// InvalidTokenError represents an error when a token is invalid/expired
type InvalidTokenError struct {
	Repository GitRepository
	TokenKey   string
	Message    string
}

func (e *InvalidTokenError) Error() string {
	return e.Message
}

// isAuthenticationError checks if the error indicates authentication failure
func isAuthenticationError(output string) bool {
	authErrors := []string{
		"Authentication failed",
		"invalid username or password",
		"remote: Invalid username or password",
		"fatal: Authentication failed for",
		"remote: Support for password authentication was removed",
		"Permission denied (publickey)",
		"fatal: could not read Username",
		"fatal: repository does not exist",
		"HTTP 401",
		"HTTP 403",
	}
	
	lowerOutput := strings.ToLower(output)
	for _, errMsg := range authErrors {
		if strings.Contains(lowerOutput, strings.ToLower(errMsg)) {
			return true
		}
	}
	return false
}

// validateAndCleanupToken validates a token and removes it if invalid
func (tm *GitTokenManager) validateAndCleanupToken(s *server.Server, repo GitRepository) (string, error) {
	if repo.GitHubTokenKey == "" {
		return "", fmt.Errorf("no token key specified")
	}
	
	token, err := tm.GetToken(repo.GitHubTokenKey)
	if err != nil {
		return "", err
	}
	
	// Validate the token
	if err := tm.ValidateToken(token); err != nil {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Token validation failed for %s: %s", repo.GitHubTokenKey, err.Error()))
		
		// Delete the invalid token
		if deleteErr := tm.DeleteToken(repo.GitHubTokenKey); deleteErr != nil {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Warning: Failed to delete invalid token: %s", deleteErr.Error()))
		} else {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Removed invalid token for key: %s", repo.GitHubTokenKey))
		}
		
		return "", &InvalidTokenError{
			Repository: repo,
			TokenKey:   repo.GitHubTokenKey,
			Message:    fmt.Sprintf("Token for key '%s' is invalid or expired", repo.GitHubTokenKey),
		}
	}
	
	return token, nil
}