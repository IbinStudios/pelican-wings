package router

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"regexp"
	"net/http"

	"github.com/pelican-dev/wings/server"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/pelican-dev/wings/router/middleware"
)

// Helper function to attempt git clone with a specific URL
func attemptGitClone(c *gin.Context, s *server.Server, repo GitRepository, cloneURL, cleanPath, parentPath, basePath string) (bool, string, error) {
	// Build clone command
	var cloneCmd *exec.Cmd
	if repo.Branch != "" && repo.Branch != "main" && repo.Branch != "master" {
		cloneCmd = exec.CommandContext(c.Request.Context(), "git", "clone", "-b", repo.Branch, cloneURL, filepath.Join(basePath, cleanPath))
	} else {
		cloneCmd = exec.CommandContext(c.Request.Context(), "git", "clone", cloneURL, filepath.Join(basePath, cleanPath))
	}

	cloneCmd.Dir = parentPath

	// Set environment to avoid interactive prompts
	cloneCmd.Env = append(cloneCmd.Env,
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
	)

	var stdout, stderr bytes.Buffer
	cloneCmd.Stdout = &stdout
	cloneCmd.Stderr = &stderr

	err := cloneCmd.Run()
	stdoutStr := strings.TrimSpace(stdout.String())
	stderrStr := strings.TrimSpace(stderr.String())

	// Combine output for return
	var combinedOutput strings.Builder
	if stdoutStr != "" {
		combinedOutput.WriteString(stdoutStr)
		combinedOutput.WriteString("\n")
	}
	if stderrStr != "" {
		combinedOutput.WriteString(stderrStr)
		combinedOutput.WriteString("\n")
	}

	if err != nil {
		return false, combinedOutput.String(), fmt.Errorf("git clone failed: %s", err.Error())
	}

	// Show successful output
	if stdoutStr != "" {
		lines := strings.Split(stdoutStr, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] %s", line))
			}
		}
	}

	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] SUCCESS: %s cloned to %s", repo.CleanName, cleanPath))
	return true, combinedOutput.String(), nil
}

// Helper function to attempt git pull
func attemptGitPull(c *gin.Context, s *server.Server, fullPath, currentBranch string) (bool, string, error) {
	// Try different git pull strategies
	strategies := []struct {
		name        string
		description string
		commands    [][]string
	}{
		{
			name:        "simple_pull",
			description: "Simple git pull",
			commands: [][]string{
				{"git", "pull"},
			},
		},
		{
			name:        "stash_pull_pop",
			description: "Stash changes, pull, then pop stash",
			commands: [][]string{
				{"git", "stash", "push", "-m", "Auto-stash before pull"},
				{"git", "pull"},
				{"git", "stash", "pop"},
			},
		},
		{
			name:        "fetch_reset",
			description: "Fetch and reset to origin",
			commands: [][]string{
				{"git", "fetch", "--all"},
				{"git", "reset", "--hard", "origin/" + currentBranch},
			},
		},
		{
			name:        "reset_clean_pull",
			description: "Reset hard, clean, then pull",
			commands: [][]string{
				{"git", "reset", "--hard", "HEAD"},
				{"git", "clean", "-fd"},
				{"git", "pull"},
			},
		},
	}

	var lastError error
	var lastOutput string

	for _, strategy := range strategies {
		strategySuccess := true
		var combinedOutput strings.Builder

		for _, cmdArgs := range strategy.commands {
			cmd := exec.CommandContext(c.Request.Context(), cmdArgs[0], cmdArgs[1:]...)
			cmd.Dir = fullPath

			// Set environment to avoid interactive prompts
			cmd.Env = append(cmd.Env,
				"GIT_TERMINAL_PROMPT=0",
				"GCM_INTERACTIVE=never",
			)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			stdoutStr := strings.TrimSpace(stdout.String())
			stderrStr := strings.TrimSpace(stderr.String())

			// Add output to combined results
			if stdoutStr != "" {
				combinedOutput.WriteString(stdoutStr)
				combinedOutput.WriteString("\n")
			}
			if stderrStr != "" {
				combinedOutput.WriteString(stderrStr)
				combinedOutput.WriteString("\n")
			}

			if err != nil {
				strategySuccess = false
				lastError = err
				lastOutput = combinedOutput.String()
				break
			} else {
				// Show command output
				if stdoutStr != "" {
					lines := strings.Split(stdoutStr, "\n")
					for _, line := range lines {
						if strings.TrimSpace(line) != "" {
							s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] %s", line))
						}
					}
				}
			}
		}

		if strategySuccess {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] SUCCESS: %s completed successfully", strategy.description))
			return true, combinedOutput.String(), nil
		}
	}

	// All strategies failed
	return false, lastOutput, lastError
}

// Helper function to update remote URL with token
func updateRemoteWithToken(c *gin.Context, s *server.Server, fullPath, token string) error {
	s.PublishConsoleOutputFromDaemon("[Git Update] Updating remote URL to use access token...")

	// Get current remote URL
	remoteCmd := exec.CommandContext(c.Request.Context(), "git", "remote", "get-url", "origin")
	remoteCmd.Dir = fullPath
	remoteOutput, remoteErr := remoteCmd.CombinedOutput()

	if remoteErr != nil {
		return fmt.Errorf("failed to get remote URL: %s", remoteErr.Error())
	}

	currentRemote := strings.TrimSpace(string(remoteOutput))
	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Current remote: %s", sanitizeGitURL(currentRemote)))

	// Convert SSH URL to HTTPS with token if needed
	var newRemoteURL string
	if strings.HasPrefix(currentRemote, "git@github.com:") {
		// Convert SSH to HTTPS
		repoPath := strings.TrimPrefix(currentRemote, "git@github.com:")
		repoPath = strings.TrimSuffix(repoPath, ".git")
		newRemoteURL = fmt.Sprintf("https://%s@github.com/%s.git", token, repoPath)
	} else if strings.Contains(currentRemote, "github.com") && !strings.Contains(currentRemote, "@") {
		// Add token to existing HTTPS URL
		newRemoteURL = strings.Replace(currentRemote, "https://github.com/", fmt.Sprintf("https://%s@github.com/", token), 1)
	} else if strings.Contains(currentRemote, "@github.com") {
		// URL already has credentials, update the token
		re := regexp.MustCompile(`https://[^@]*@github\.com/`)
		newRemoteURL = re.ReplaceAllString(currentRemote, fmt.Sprintf("https://%s@github.com/", token))
	} else {
		newRemoteURL = currentRemote // Keep as-is if it's not a GitHub URL
	}

	if newRemoteURL != currentRemote {
		setUrlCmd := exec.CommandContext(c.Request.Context(), "git", "remote", "set-url", "origin", newRemoteURL)
		setUrlCmd.Dir = fullPath

		setUrlOutput, setUrlErr := setUrlCmd.CombinedOutput()
		if setUrlErr != nil {
			return fmt.Errorf("failed to update remote URL: %s %s", setUrlErr.Error(), setUrlOutput)
		}
		s.PublishConsoleOutputFromDaemon("[Git Update] Remote URL updated successfully")
	}

	return nil
}

// executeGitCloneWithRepo clones a repository, trying public first then with token if needed
func executeGitCloneWithRepo(c *gin.Context, s *server.Server, repo GitRepository) (bool, string, error) {
	basePath := s.Filesystem().Path()
	cleanPath := strings.TrimPrefix(strings.TrimSpace(repo.Path), "/")
	parentPath := filepath.Dir(filepath.Join(basePath, cleanPath))

	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Cloning %s to: %s", repo.CleanName, cleanPath))

	// Construct clone URL without token first (for public repos)
	repoURL := repo.GitRepo
	if !strings.HasSuffix(repoURL, ".git") {
		repoURL += ".git"
	}

	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Cloning from: %s", sanitizeGitURL(repoURL)))
	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Target path: %s", cleanPath))

	// Ensure parent directory exists
	if err := os.MkdirAll(parentPath, 0755); err != nil {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] ERROR: Failed to create parent directory: %s", err.Error()))
		return false, "", fmt.Errorf("failed to create parent directory: %s", err.Error())
	}

	// First attempt: Try without token (for public repos)
	success, output, err := attemptGitClone(c, s, repo, repoURL, cleanPath, parentPath, basePath)
	if success {
		return true, output, nil
	}

	// If clone failed and we have a token key, validate and use token
	if repo.GitHubTokenKey != "" {
		s.PublishConsoleOutputFromDaemon("[Git Update] Public clone failed, trying with authentication token...")

		tm := NewGitTokenManager(s)
		
		// Validate token and clean up if invalid
		token, tokenErr := tm.validateAndCleanupToken(s, repo)
		if tokenErr != nil {
			// Check if it's an invalid token error
			if _, ok := tokenErr.(*InvalidTokenError); ok {
				return false, output, tokenErr
			}
			
			// If token doesn't exist, return missing token error
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] No token available: %s", tokenErr.Error()))
			return false, output, &MissingTokenError{
				Repository: repo,
				Message:    fmt.Sprintf("Repository requires authentication but no token found for key: %s", repo.GitHubTokenKey),
			}
		}

		// Try with validated token
		tokenURL := strings.Replace(repoURL, "https://github.com/", fmt.Sprintf("https://%s@github.com/", token), 1)
		success, output, err = attemptGitClone(c, s, repo, tokenURL, cleanPath, parentPath, basePath)
		if success {
			return true, output, nil
		}
		
		// Check if the failure was due to authentication
		if isAuthenticationError(output) {
			s.PublishConsoleOutputFromDaemon("[Git Update] Authentication failed with token, removing invalid token...")
			
			// Delete the token and return invalid token error
			if deleteErr := tm.DeleteToken(repo.GitHubTokenKey); deleteErr != nil {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Warning: Failed to delete invalid token: %s", deleteErr.Error()))
			} else {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Removed invalid token for key: %s", repo.GitHubTokenKey))
			}
			
			return false, output, &InvalidTokenError{
				Repository: repo,
				TokenKey:   repo.GitHubTokenKey,
				Message:    fmt.Sprintf("Token for key '%s' failed authentication and was removed", repo.GitHubTokenKey),
			}
		}
	}

	// Both attempts failed - if no token key, it's probably a genuine error
	if repo.GitHubTokenKey == "" {
		return false, output, err
	}

	// If we have a token key but validation succeeded, return the git error
	return false, output, err
}


// executeGitPullWithRepo executes git pull, trying public first then with token if needed
func executeGitPullWithRepo(c *gin.Context, s *server.Server, repo GitRepository) (bool, string, error) {
	// Get the absolute path to the repository
	basePath := s.Filesystem().Path()
	cleanPath := strings.TrimPrefix(strings.TrimSpace(repo.Path), "/")
	fullPath := filepath.Join(basePath, cleanPath)

	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Working with filesystem path: %s", cleanPath))

	// First, handle Git ownership security and check if it's a valid git repository
	s.PublishConsoleOutputFromDaemon("[Git Update] Checking git repository status...")

	statusCmd := exec.CommandContext(c.Request.Context(), "git", "status", "--porcelain")
	statusCmd.Dir = fullPath

	statusOutput, statusErr := statusCmd.CombinedOutput()
	statusStr := strings.TrimSpace(string(statusOutput))

	// Check if this is a "dubious ownership" error
	if statusErr != nil && strings.Contains(string(statusOutput), "dubious ownership") {
		s.PublishConsoleOutputFromDaemon("[Git Update] Detected dubious ownership issue, adding to safe directory...")

		// Add this directory to git safe directories
		safeCmd := exec.CommandContext(c.Request.Context(), "git", "config", "--global", "--add", "safe.directory", fullPath)
		safeOutput, safeErr := safeCmd.CombinedOutput()

		if safeErr != nil {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] ERROR: Failed to add safe directory: %s", safeErr.Error()))
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Safe directory output: %s", string(safeOutput)))
			return false, statusStr, fmt.Errorf("failed to configure git safe directory: %s", safeErr.Error())
		}

		s.PublishConsoleOutputFromDaemon("[Git Update] Successfully added to safe directory, retrying status check...")

		// Retry the status command
		statusCmd = exec.CommandContext(c.Request.Context(), "git", "status", "--porcelain")
		statusCmd.Dir = fullPath
		statusOutput, statusErr = statusCmd.CombinedOutput()
		statusStr = strings.TrimSpace(string(statusOutput))
	}

	if statusErr != nil {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] ERROR: Not a git repository or git command failed: %s", statusErr.Error()))
		if statusStr != "" {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Git status output: %s", statusStr))
		}
		return false, statusStr, fmt.Errorf("git repository check failed: %s", statusErr.Error())
	}

	s.PublishConsoleOutputFromDaemon("[Git Update] Git repository validated successfully")

	// Show current branch
	branchCmd := exec.CommandContext(c.Request.Context(), "git", "rev-parse", "--abbrev-ref", "HEAD")
	branchCmd.Dir = fullPath
	branchOutput, _ := branchCmd.CombinedOutput()
	currentBranch := strings.TrimSpace(string(branchOutput))
	if currentBranch != "" {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Current branch: %s", currentBranch))
	}

	// Show uncommitted changes if any
	if statusStr != "" {
		s.PublishConsoleOutputFromDaemon("[Git Update] Uncommitted changes detected:")
		lines := strings.Split(statusStr, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update]   %s", line))
			}
		}
	}

	// First attempt: Try git pull without updating remote URL (for public repos)
	s.PublishConsoleOutputFromDaemon("[Git Update] Attempting git pull without authentication...")
	success, output, err := attemptGitPull(c, s, fullPath, currentBranch)
	if success {
		return true, output, nil
	}

	// If pull failed and we have a token key, validate and use token
	if repo.GitHubTokenKey != "" {
		s.PublishConsoleOutputFromDaemon("[Git Update] Public pull failed, trying with authentication token...")

		tm := NewGitTokenManager(s)
		
		// Validate token and clean up if invalid
		token, tokenErr := tm.validateAndCleanupToken(s, repo)
		if tokenErr != nil {
			// Check if it's an invalid token error
			if _, ok := tokenErr.(*InvalidTokenError); ok {
				return false, output, tokenErr
			}
			
			// If token doesn't exist, return missing token error
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] No token available: %s", tokenErr.Error()))
			return false, output, &MissingTokenError{
				Repository: repo,
				Message:    fmt.Sprintf("Repository requires authentication but no token found for key: %s", repo.GitHubTokenKey),
			}
		}

		// Update remote URL with validated token and try again
		if updateErr := updateRemoteWithToken(c, s, fullPath, token); updateErr != nil {
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Failed to update remote URL: %s", updateErr.Error()))
			return false, output, fmt.Errorf("failed to update remote URL: %s", updateErr.Error())
		}

		success, output, err = attemptGitPull(c, s, fullPath, currentBranch)
		if success {
			return true, output, nil
		}
		
		// Check if the failure was due to authentication
		if isAuthenticationError(output) {
			s.PublishConsoleOutputFromDaemon("[Git Update] Authentication failed with token, removing invalid token...")
			
			// Delete the token and return invalid token error
			if deleteErr := tm.DeleteToken(repo.GitHubTokenKey); deleteErr != nil {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Warning: Failed to delete invalid token: %s", deleteErr.Error()))
			} else {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Removed invalid token for key: %s", repo.GitHubTokenKey))
			}
			
			return false, output, &InvalidTokenError{
				Repository: repo,
				TokenKey:   repo.GitHubTokenKey,
				Message:    fmt.Sprintf("Token for key '%s' failed authentication and was removed", repo.GitHubTokenKey),
			}
		}
	}

	// Both attempts failed
	return false, output, err
}
// postServerGitPull handles git pull/clone operations with per-repo token keys
func postServerGitPull(c *gin.Context) {
	s := middleware.ExtractServer(c)

	s.PublishConsoleOutputFromDaemon("---------- Git Update Started ----------")

	var data struct {
		Repositories []GitRepository   `json:"repositories"`
		Tokens       map[string]string `json:"tokens,omitempty"`
	}

	if err := c.BindJSON(&data); err != nil {
		s.PublishConsoleOutputFromDaemon("[Git Update] ERROR: Failed to parse request data: " + err.Error())
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data: " + err.Error(),
		})
		return
	}

	if len(data.Repositories) == 0 {
		s.PublishConsoleOutputFromDaemon("[Git Update] ERROR: No repositories specified for git pull")
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No repositories were specified for git pull.",
		})
		return
	}

	// Store any new tokens provided
	tm := NewGitTokenManager(s)
	if data.Tokens != nil {
		log.WithField("token_count", len(data.Tokens)).Info("Storing provided tokens")
		for key, token := range data.Tokens {
			if err := tm.StoreToken(key, token); err != nil {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Warning: Failed to store token for %s: %s", key, err.Error()))
				log.WithFields(log.Fields{
					"key":   key,
					"error": err.Error(),
				}).Warn("Failed to store token")
			} else {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Stored token for key: %s", key))
				log.WithField("key", key).Info("Successfully stored token")
			}
		}
	}

	results := make([]gin.H, 0, len(data.Repositories))
	missingTokenRepos := make([]GitRepository, 0)
	invalidTokenRepos := make([]GitRepository, 0)

	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Starting git pull for %d repositories...", len(data.Repositories)))
	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Server filesystem base: %s", s.Filesystem().Path()))

	// Execute git operations for each repository
	for i, repo := range data.Repositories {
		result := gin.H{
			"path":       repo.Path,
			"clean_name": repo.CleanName,
		}

		cleanPath := strings.TrimPrefix(strings.TrimSpace(repo.Path), "/")

		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] (%d/%d) Processing: %s", i+1, len(data.Repositories), repo.CleanName))

		// Use the server's filesystem to check if path exists
		fs := s.Filesystem()

		// Check if the path exists and if it's a git repository
		pathExists := true
		isGitRepo := false

		if _, err := fs.Stat(cleanPath); err != nil {
			pathExists = false
			s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Path does not exist: %s (will attempt to clone)", cleanPath))
		} else {
			// Check if it's a git repository
			gitPath := filepath.Join(cleanPath, ".git")
			if _, err := fs.Stat(gitPath); err == nil {
				isGitRepo = true
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Found existing git repository: %s", cleanPath))
			} else {
				s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Path exists but is not a git repository: %s", cleanPath))
			}
		}

		// Execute git operations
		if !pathExists || !isGitRepo {
			// Need to clone the repository
			success, output, gitErr := executeGitCloneWithRepo(c, s, repo)

			result["success"] = success
			result["output"] = output
			result["clean_path"] = cleanPath
			result["action"] = "clone"

			if gitErr != nil {
				// Check error types
				if missingTokenErr, ok := gitErr.(*MissingTokenError); ok {
					log.WithField("repo", missingTokenErr.Repository.CleanName).Info("Missing token detected for repository")
					missingTokenRepos = append(missingTokenRepos, missingTokenErr.Repository)
				} else if invalidTokenErr, ok := gitErr.(*InvalidTokenError); ok {
					log.WithField("repo", invalidTokenErr.Repository.CleanName).Info("Invalid token detected for repository")
					invalidTokenRepos = append(invalidTokenRepos, invalidTokenErr.Repository)
				}
				result["error"] = gitErr.Error()
			}
		} else {
			// Repository exists, do a pull
			success, output, gitErr := executeGitPullWithRepo(c, s, repo)

			result["success"] = success
			result["output"] = output
			result["clean_path"] = cleanPath
			result["action"] = "pull"

			if gitErr != nil {
				// Check error types
				if missingTokenErr, ok := gitErr.(*MissingTokenError); ok {
					log.WithField("repo", missingTokenErr.Repository.CleanName).Info("Missing token detected for repository")
					missingTokenRepos = append(missingTokenRepos, missingTokenErr.Repository)
				} else if invalidTokenErr, ok := gitErr.(*InvalidTokenError); ok {
					log.WithField("repo", invalidTokenErr.Repository.CleanName).Info("Invalid token detected for repository")
					invalidTokenRepos = append(invalidTokenRepos, invalidTokenErr.Repository)
				}
				result["error"] = gitErr.Error()
			}
		}

		results = append(results, result)
	}

	// Combine missing and invalid token repos for response
	allMissingTokenRepos := make([]GitRepository, 0, len(missingTokenRepos)+len(invalidTokenRepos))
	allMissingTokenRepos = append(allMissingTokenRepos, missingTokenRepos...)
	allMissingTokenRepos = append(allMissingTokenRepos, invalidTokenRepos...)

	// If we have missing or invalid tokens, return 428 status
	if len(allMissingTokenRepos) > 0 {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Missing or invalid tokens for %d repositories", len(allMissingTokenRepos)))
		log.WithField("missing_count", len(allMissingTokenRepos)).Info("Returning 428 for missing/invalid tokens")

		c.JSON(http.StatusPreconditionRequired, gin.H{
			"error":          "Missing or invalid GitHub tokens for repositories",
			"missing_tokens": allMissingTokenRepos,
		})
		return
	}

	// Send completion message to console
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

	s.PublishConsoleOutputFromDaemon("---------- Git Update Completed ----------")
	s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Results: %d/%d repositories updated successfully", successCount, len(data.Repositories)))

	if len(failedRepos) > 0 {
		s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Failed repositories: %s", strings.Join(failedRepos, ", ")))
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