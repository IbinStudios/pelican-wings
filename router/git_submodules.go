package router

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/pelican-dev/wings/router/middleware"

	"github.com/pelican-dev/wings/server"
)

// executeGitSubmoduleUpdate updates git submodules for a repository
func executeGitSubmoduleUpdate(c *gin.Context, s *server.Server, repo GitRepository) (bool, string, error) {
	basePath := s.Filesystem().Path()
	cleanPath := strings.TrimPrefix(strings.TrimSpace(repo.Path), "/")
	fullPath := filepath.Join(basePath, cleanPath)

	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] Updating submodules for %s", repo.CleanName))

	// Check if this is a valid git repository
	statusCmd := exec.CommandContext(c.Request.Context(), "git", "status", "--porcelain")
	statusCmd.Dir = fullPath

	var statusStdout, statusStderr bytes.Buffer
	statusCmd.Stdout = &statusStdout
	statusCmd.Stderr = &statusStderr

	if err := statusCmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(statusStderr.String())

		// Handle dubious ownership issue
		if strings.Contains(stderrStr, "dubious ownership") {
			s.PublishConsoleOutputFromDaemon("[Git Submodules] Adding to git safe directory...")

			safeCmd := exec.CommandContext(c.Request.Context(), "git", "config", "--global", "--add", "safe.directory", fullPath)
			if err := safeCmd.Run(); err != nil {
				return false, "", fmt.Errorf("failed to configure git safe directory: %s", err.Error())
			}

			// Retry status check
			if err := statusCmd.Run(); err != nil {
				return false, "", fmt.Errorf("git repository check failed: %s", err.Error())
			}
		} else {
			return false, "", fmt.Errorf("not a valid git repository: %s", err.Error())
		}
	}

	// Check if .gitmodules exists
	gitmodulesPath := filepath.Join(fullPath, ".gitmodules")
	if _, err := os.Stat(gitmodulesPath); os.IsNotExist(err) {
		return true, "No submodules found", nil
	}

	// Check if we need tokens for private repositories
	gitmodulesContent, err := os.ReadFile(gitmodulesPath)
	if err != nil {
		return false, "", fmt.Errorf("failed to read .gitmodules: %s", err.Error())
	}

	needsToken := strings.Contains(string(gitmodulesContent), "git@github.com:") ||
		strings.Contains(string(gitmodulesContent), "github.com/ibinstudios")

	var token string
	if needsToken && repo.GitHubTokenKey != "" {
		tm := NewGitTokenManager(s)
		
		// Validate token and clean up if invalid
		validatedToken, tokenErr := tm.validateAndCleanupToken(s, repo)
		if tokenErr != nil {
			// Check if it's an invalid token error
			if _, ok := tokenErr.(*InvalidTokenError); ok {
				return false, "", tokenErr
			}
			
			// If token doesn't exist, return missing token error
			if needsToken {
				return false, "", &MissingTokenError{
					Repository: repo,
					Message:    fmt.Sprintf("Submodules require authentication but no token found for key: %s", repo.GitHubTokenKey),
				}
			}
		} else {
			token = validatedToken
		}
	}

	// Update .gitmodules with token if needed
	if token != "" {
		if err := updateSubmoduleURLsWithToken(c, s, fullPath, token); err != nil {
			return false, "", fmt.Errorf("failed to configure submodule authentication: %s", err.Error())
		}
		// Ensure cleanup happens regardless of outcome
		defer restoreGitmodules(s, fullPath)
	}

	// Try submodule update strategies
	strategies := []struct {
		name     string
		commands [][]string
	}{
		{
			name: "Initialize and update submodules",
			commands: [][]string{
				{"git", "submodule", "init"},
				{"git", "submodule", "update", "--recursive"},
			},
		},
		{
			name: "Sync and update submodules",
			commands: [][]string{
				{"git", "submodule", "sync", "--recursive"},
				{"git", "submodule", "update", "--init", "--recursive"},
			},
		},
		{
			name: "Force update submodules",
			commands: [][]string{
				{"git", "submodule", "update", "--init", "--recursive", "--force"},
			},
		},
	}

	var lastOutput string
	var lastError error

	for _, strategy := range strategies {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] Trying: %s", strategy.name))
		strategySuccess := true
		var combinedOutput strings.Builder

		for _, cmdArgs := range strategy.commands {
			cmd := exec.CommandContext(c.Request.Context(), cmdArgs[0], cmdArgs[1:]...)
			cmd.Dir = fullPath
			cmd.Env = append(os.Environ(),
				"GIT_TERMINAL_PROMPT=0",
				"GCM_INTERACTIVE=never",
			)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			stdoutStr := strings.TrimSpace(stdout.String())
			stderrStr := strings.TrimSpace(stderr.String())

			if stdoutStr != "" {
				combinedOutput.WriteString(stdoutStr)
				combinedOutput.WriteString("\n")
			}
			if stderrStr != "" {
				combinedOutput.WriteString(stderrStr)
				combinedOutput.WriteString("\n")
			}

			if err != nil {
				// Check if this is an authentication error and we have a token
				if isAuthenticationError(stderrStr) && repo.GitHubTokenKey != "" && token != "" {
					s.PublishConsoleOutputFromDaemon("[Git Submodules] Authentication failed with token, removing invalid token...")
					
					tm := NewGitTokenManager(s)
					if deleteErr := tm.DeleteToken(repo.GitHubTokenKey); deleteErr != nil {
						s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] Warning: Failed to delete invalid token: %s", deleteErr.Error()))
					} else {
						s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] Removed invalid token for key: %s", repo.GitHubTokenKey))
					}
					
					return false, combinedOutput.String(), &InvalidTokenError{
						Repository: repo,
						TokenKey:   repo.GitHubTokenKey,
						Message:    fmt.Sprintf("Token for key '%s' failed authentication and was removed", repo.GitHubTokenKey),
					}
				}
				
				strategySuccess = false
				lastError = err
				lastOutput = combinedOutput.String()
				break
			}

			// Show successful output
			if stdoutStr != "" {
				lines := strings.Split(stdoutStr, "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] %s", line))
					}
				}
			}
		}

		if strategySuccess {
			// Verify submodules were actually updated
			statusCmd := exec.CommandContext(c.Request.Context(), "git", "submodule", "status")
			statusCmd.Dir = fullPath
			statusOutput, statusErr := statusCmd.CombinedOutput()
			if statusErr == nil {
				statusStr := strings.TrimSpace(string(statusOutput))
				if statusStr != "" {
					s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] SUCCESS: %s", strategy.name))
					return true, combinedOutput.String(), nil
				}
			}
		}
	}

	// All strategies failed
	return false, lastOutput, lastError
}


// updateSubmoduleURLsWithToken temporarily modifies .gitmodules with authentication tokens
func updateSubmoduleURLsWithToken(c *gin.Context, s *server.Server, fullPath, token string) error {
	gitmodulesPath := filepath.Join(fullPath, ".gitmodules")

	// Read .gitmodules file
	content, err := os.ReadFile(gitmodulesPath)
	if err != nil {
		return fmt.Errorf("failed to read .gitmodules: %s", err.Error())
	}

	originalContent := string(content)

	// Create backup
	backupPath := gitmodulesPath + ".backup"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %s", err.Error())
	}

	// Parse and modify URLs
	lines := strings.Split(originalContent, "\n")
	conversionsCount := 0

	for i, line := range lines {
		if strings.Contains(strings.TrimSpace(line), "url = ") {
			parts := strings.SplitN(line, "url = ", 2)
			if len(parts) == 2 {
				originalURL := strings.TrimSpace(parts[1])
				var newURL string

				if strings.HasPrefix(originalURL, "git@github.com:") {
					// Convert SSH to HTTPS with token
					repoPath := strings.TrimPrefix(originalURL, "git@github.com:")
					if !strings.HasSuffix(repoPath, ".git") {
						repoPath += ".git"
					}
					newURL = fmt.Sprintf("https://%s@github.com/%s", token, repoPath)
					conversionsCount++
				} else if strings.HasPrefix(originalURL, "https://github.com/") && !strings.Contains(originalURL, "@github.com") {
					// Add token to existing HTTPS URL
					newURL = strings.Replace(originalURL, "https://github.com/", fmt.Sprintf("https://%s@github.com/", token), 1)
					conversionsCount++
				} else if strings.Contains(originalURL, "@github.com") {
					// Update existing token
					re := regexp.MustCompile(`https://[^@]*@github\.com/`)
					newURL = re.ReplaceAllString(originalURL, fmt.Sprintf("https://%s@github.com/", token))
					conversionsCount++
				}

				if newURL != "" {
					lines[i] = strings.Replace(line, originalURL, newURL, 1)
				}
			}
		}
	}

	if conversionsCount > 0 {
		// Write modified content to .gitmodules
		modifiedContent := strings.Join(lines, "\n")
		if err := os.WriteFile(gitmodulesPath, []byte(modifiedContent), 0644); err != nil {
			return fmt.Errorf("failed to write modified .gitmodules: %s", err.Error())
		}
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] Configured authentication for %d submodule(s)", conversionsCount))
	}

	return nil
}

// restoreGitmodules restores the original .gitmodules file from backup
func restoreGitmodules(s *server.Server, fullPath string) {
	gitmodulesPath := filepath.Join(fullPath, ".gitmodules")
	backupPath := gitmodulesPath + ".backup"

	if _, err := os.Stat(backupPath); err == nil {
		if err := os.Rename(backupPath, gitmodulesPath); err != nil {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Submodules] Warning: Failed to restore .gitmodules: %s", err.Error()))
		}
	}
}

// checkHasSubmodules checks if a repository has submodules
func checkHasSubmodules(s *server.Server, repo GitRepository) bool {
	basePath := s.Filesystem().Path()
	cleanPath := strings.TrimPrefix(strings.TrimSpace(repo.Path), "/")
	fullPath := filepath.Join(basePath, cleanPath)

	gitmodulesPath := filepath.Join(fullPath, ".gitmodules")
	if _, err := os.Stat(gitmodulesPath); os.IsNotExist(err) {
		return false
	}
	return true
}

// postServerGitSubmodules handles git submodule operations
func postServerGitSubmodules(c *gin.Context) {
	s := middleware.ExtractServer(c)

	var data struct {
		Repositories []GitRepository   `json:"repositories"`
		Tokens       map[string]string `json:"tokens,omitempty"`
	}

	if err := c.BindJSON(&data); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data: " + err.Error(),
		})
		return
	}

	if len(data.Repositories) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No repositories were specified for submodule update.",
		})
		return
	}

	// Store any new tokens provided
	tm := NewGitTokenManager(s)
	if data.Tokens != nil {
		for key, token := range data.Tokens {
			if err := tm.StoreToken(key, token); err != nil {
				log.WithFields(log.Fields{
					"key":   key,
					"error": err.Error(),
				}).Warn("Failed to store token")
			}
		}
	}

	results := make([]gin.H, 0, len(data.Repositories))
	missingTokenRepos := make([]GitRepository, 0)
	invalidTokenRepos := make([]GitRepository, 0)

	// Process each repository
	for _, repo := range data.Repositories {
		result := gin.H{
			"path":           repo.Path,
			"clean_name":     repo.CleanName,
			"has_submodules": checkHasSubmodules(s, repo),
		}

		if !result["has_submodules"].(bool) {
			result["success"] = true
			result["output"] = "No submodules found"
			result["action"] = "skip"
		} else {
			success, output, err := executeGitSubmoduleUpdate(c, s, repo)

			result["success"] = success
			result["output"] = output
			result["action"] = "update"

			if err != nil {
				if missingTokenErr, ok := err.(*MissingTokenError); ok {
					missingTokenRepos = append(missingTokenRepos, missingTokenErr.Repository)
				} else if invalidTokenErr, ok := err.(*InvalidTokenError); ok {
					invalidTokenRepos = append(invalidTokenRepos, invalidTokenErr.Repository)
				}
				result["error"] = err.Error()
			}
		}

		results = append(results, result)
	}

	// Combine missing and invalid token repos for response
	allMissingTokenRepos := make([]GitRepository, 0, len(missingTokenRepos)+len(invalidTokenRepos))
	allMissingTokenRepos = append(allMissingTokenRepos, missingTokenRepos...)
	allMissingTokenRepos = append(allMissingTokenRepos, invalidTokenRepos...)

	// Handle missing or invalid tokens
	if len(allMissingTokenRepos) > 0 {
		c.JSON(http.StatusPreconditionRequired, gin.H{
			"error":          "Missing or invalid GitHub tokens for submodule repositories",
			"missing_tokens": allMissingTokenRepos,
		})
		return
	}

	// Calculate results summary
	successCount := 0
	failedRepos := make([]string, 0)

	for _, result := range results {
		if success, ok := result["success"].(bool); ok && success {
			successCount++
		} else {
			if name, ok := result["clean_name"].(string); ok {
				failedRepos = append(failedRepos, name)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"summary": gin.H{
			"total":        len(data.Repositories),
			"success":      successCount,
			"failed":       len(data.Repositories) - successCount,
			"failed_repos": failedRepos,
		},
	})
}