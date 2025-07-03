package router

import (
        "bufio"
        "context"
        "io"
        "mime/multipart"
        "net/http"
        "net/url"
        "os"
        "os/exec"
        "path"
        "path/filepath"
        "strconv"
        "strings"
        "fmt"
        "bytes"
        "regexp"

        "emperror.dev/errors"
        "github.com/apex/log"
        "github.com/gin-gonic/gin"
        "golang.org/x/sync/errgroup"

        "github.com/pelican-dev/wings/config"
        "github.com/pelican-dev/wings/internal/models"
        "github.com/pelican-dev/wings/internal/ufs"
        "github.com/pelican-dev/wings/router/downloader"
        "github.com/pelican-dev/wings/router/middleware"
        "github.com/pelican-dev/wings/router/tokens"
        "github.com/pelican-dev/wings/server"
        "github.com/pelican-dev/wings/server/filesystem"
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
        strategies := []struct{
                name        string
                description string
                commands    [][]string
        }{
                {
                        name: "simple_pull",
                        description: "Simple git pull",
                        commands: [][]string{
                                {"git", "pull"},
                        },
                },
                {
                        name: "stash_pull_pop",
                        description: "Stash changes, pull, then pop stash",
                        commands: [][]string{
                                {"git", "stash", "push", "-m", "Auto-stash before pull"},
                                {"git", "pull"},
                                {"git", "stash", "pop"},
                        },
                },
                {
                        name: "fetch_reset",
                        description: "Fetch and reset to origin",
                        commands: [][]string{
                                {"git", "fetch", "--all"},
                                {"git", "reset", "--hard", "origin/" + currentBranch},
                        },
                },
                {
                        name: "reset_clean_pull",
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

        // If clone failed and we have a token key, check if token is available
        if repo.GitHubTokenKey != "" {
                s.PublishConsoleOutputFromDaemon("[Git Update] Public clone failed, trying with authentication token...")

                tm := NewGitTokenManager(s)
                token, tokenErr := tm.GetToken(repo.GitHubTokenKey)
                if tokenErr != nil {
                        s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] No token available: %s", tokenErr.Error()))

                        // Return a special error that indicates missing token
                        return false, output, &MissingTokenError{
                                Repository: repo,
                                Message:    fmt.Sprintf("Repository requires authentication but no token found for key: %s", repo.GitHubTokenKey),
                        }
                }

                // Try with token
                tokenURL := strings.Replace(repoURL, "https://github.com/", fmt.Sprintf("https://%s@github.com/", token), 1)
                success, output, err = attemptGitClone(c, s, repo, tokenURL, cleanPath, parentPath, basePath)
                if success {
                        return true, output, nil
                }
        }

        // Both attempts failed - if no token key, it's probably a genuine error
        if repo.GitHubTokenKey == "" {
                return false, output, err
        }

        // If we have a token key but token exists, return the git error
        return false, output, err
}

// executeGitPullWithRepo executes git pull, trying public first then with token if needed
func executeGitPullWithRepo(c *gin.Context, s *server.Server, repo GitRepository) (bool, string, error) {
        // Get the absolute path to the repository
        basePath := s.Filesystem().Path()
        cleanPath := strings.TrimPrefix(strings.TrimSpace(repo.Path), "/")
        fullPath := filepath.Join(basePath, cleanPath)

        s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Working with filesystem path: %s", fullPath))

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

        // If pull failed and we have a token key, try with token
        if repo.GitHubTokenKey != "" {
                s.PublishConsoleOutputFromDaemon("[Git Update] Public pull failed, trying with authentication token...")

                tm := NewGitTokenManager(s)
                token, tokenErr := tm.GetToken(repo.GitHubTokenKey)
                if tokenErr != nil {
                        s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] No token available: %s", tokenErr.Error()))

                        // Return a special error that indicates missing token
                        return false, output, &MissingTokenError{
                                Repository: repo,
                                Message:    fmt.Sprintf("Repository requires authentication but no token found for key: %s", repo.GitHubTokenKey),
                        }
                }

                // Update remote URL with token and try again
                if updateErr := updateRemoteWithToken(c, s, fullPath, token); updateErr != nil {
                        s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Failed to update remote URL: %s", updateErr.Error()))
                        return false, output, fmt.Errorf("failed to update remote URL: %s", updateErr.Error())
                }

                success, output, err = attemptGitPull(c, s, fullPath, currentBranch)
                if success {
                        return true, output, nil
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
                                        "key": key,
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
                                // Check if this is a missing token error
                                if missingTokenErr, ok := gitErr.(*MissingTokenError); ok {
                                        log.WithField("repo", missingTokenErr.Repository.CleanName).Info("Missing token detected for repository")
                                        missingTokenRepos = append(missingTokenRepos, missingTokenErr.Repository)
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
                                // Check if this is a missing token error
                                if missingTokenErr, ok := gitErr.(*MissingTokenError); ok {
                                        log.WithField("repo", missingTokenErr.Repository.CleanName).Info("Missing token detected for repository")
                                        missingTokenRepos = append(missingTokenRepos, missingTokenErr.Repository)
                                }
                                result["error"] = gitErr.Error()
                        }
                }

                results = append(results, result)
        }

        // If we have missing tokens, return 428 status
        if len(missingTokenRepos) > 0 {
                s.PublishConsoleOutputFromDaemon(fmt.Sprintf("[Git Update] Missing tokens for %d repositories", len(missingTokenRepos)))
                log.WithField("missing_count", len(missingTokenRepos)).Info("Returning 428 for missing tokens")

                c.JSON(http.StatusPreconditionRequired, gin.H{
                        "error":         "Missing GitHub tokens for repositories",
                        "missing_tokens": missingTokenRepos,
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

// getServerFileContents returns the contents of a file on the server.
func getServerFileContents(c *gin.Context) {
        s := middleware.ExtractServer(c)
        p := strings.TrimLeft(c.Query("file"), "/")
        if err := s.Filesystem().IsIgnored(p); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }
        f, st, err := s.Filesystem().File(p)
        if err != nil {
                if errors.Is(err, os.ErrNotExist) {
                        c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
                                "error":      "The requested resources was not found on the system.",
                                "request_id": c.Writer.Header().Get("X-Request-Id")})
                } else if strings.Contains(err.Error(), "filesystem: is a directory") {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error":      "Cannot perform that action: file is a directory.",
                                "request_id": c.Writer.Header().Get("X-Request-Id"),
                        })
                } else {
                        middleware.CaptureAndAbort(c, err)
                }
                return
        }
        defer f.Close()
        // Don't allow a named pipe to be opened.
        //
        // @see https://github.com/pterodactyl/panel/issues/4059
        if st.Mode()&os.ModeNamedPipe != 0 {
                c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                        "error": "Cannot open files of this type.",
                })
                return
        }

        c.Header("X-Mime-Type", st.Mimetype)
        c.Header("Content-Length", strconv.Itoa(int(st.Size())))
        // If a download parameter is included in the URL go ahead and attach the necessary headers
        // so that the file can be downloaded.
        if c.Query("download") != "" {
                c.Header("Content-Disposition", "attachment; filename="+strconv.Quote(st.Name()))
                c.Header("Content-Type", "application/octet-stream")
        }
        defer c.Writer.Flush()
        // If you don't do a limited reader here you will trigger a panic on write when
        // a different server process writes content to the file after you've already
        // determined the file size. This could lead to some weird content output but
        // it would technically be accurate based on the content at the time of the request.
        //
        // "http: wrote more than the declared Content-Length"
        //
        // @see https://github.com/pterodactyl/panel/issues/3131
        r := io.LimitReader(f, st.Size())
        if _, err = bufio.NewReader(r).WriteTo(c.Writer); err != nil {
                // Pretty sure this will unleash chaos on the response, but its a risk we can
                // take since a panic will at least be recovered and this should be incredibly
                // rare?
                middleware.CaptureAndAbort(c, err)
                return
        }
}

// Returns the contents of a directory for a server.
func getServerListDirectory(c *gin.Context) {
        s := middleware.ExtractServer(c)
        dir := c.Query("directory")
        if stats, err := s.Filesystem().ListDirectory(dir); err != nil {
                // If the error is that the folder does not exist return a 404.
                if errors.Is(err, os.ErrNotExist) {
                        c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
                                "error": "The requested directory was not found on the server.",
                        })
                        return
                }
                middleware.CaptureAndAbort(c, err)
        } else {
                c.JSON(http.StatusOK, stats)
        }
}

type renameFile struct {
        To   string `json:"to"`
        From string `json:"from"`
}

// Renames (or moves) files for a server.
func putServerRenameFiles(c *gin.Context) {
        s := middleware.ExtractServer(c)

        var data struct {
                Root  string       `json:"root"`
                Files []renameFile `json:"files"`
        }
        // BindJSON sends 400 if the request fails, all we need to do is return
        if err := c.BindJSON(&data); err != nil {
                return
        }

        if len(data.Files) == 0 {
                c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
                        "error": "No files to move or rename were provided.",
                })
                return
        }

        g, ctx := errgroup.WithContext(c.Request.Context())
        // Loop over the array of files passed in and perform the move or rename action against each.
        for _, p := range data.Files {
                pf := path.Join(data.Root, p.From)
                pt := path.Join(data.Root, p.To)

                g.Go(func() error {
                        select {
                        case <-ctx.Done():
                                return ctx.Err()
                        default:
                                fs := s.Filesystem()
                                // Ignore renames on a file that is on the denylist (both as the rename from or
                                // the rename to value).
                                if err := fs.IsIgnored(pf, pt); err != nil {
                                        return err
                                }
                                if err := fs.Rename(pf, pt); err != nil {
                                        // Return nil if the error is an is not exists.
                                        if errors.Is(err, os.ErrNotExist) {
                                                s.Log().WithField("error", err).
                                                        WithField("from_path", pf).
                                                        WithField("to_path", pt).
                                                        Warn("failed to rename: source or target does not exist")
                                                return nil
                                        }
                                        return err
                                }
                                return nil
                        }
                })
        }

        if err := g.Wait(); err != nil {
                if errors.Is(err, os.ErrExist) {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "Cannot move or rename file, destination already exists.",
                        })
                        return
                }

                middleware.CaptureAndAbort(c, err)
                return
        }

        c.Status(http.StatusNoContent)
}

// Copies a server file.
func postServerCopyFile(c *gin.Context) {
        s := middleware.ExtractServer(c)

        var data struct {
                Location string `json:"location"`
        }
        // BindJSON sends 400 if the request fails, all we need to do is return
        if err := c.BindJSON(&data); err != nil {
                return
        }

        if err := s.Filesystem().IsIgnored(data.Location); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }
        if err := s.Filesystem().Copy(data.Location); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }

        c.Status(http.StatusNoContent)
}

// Deletes files from a server.
func postServerDeleteFiles(c *gin.Context) {
        s := middleware.ExtractServer(c)

        var data struct {
                Root  string   `json:"root"`
                Files []string `json:"files"`
        }

        if err := c.BindJSON(&data); err != nil {
                return
        }

        if len(data.Files) == 0 {
                c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
                        "error": "No files were specified for deletion.",
                })
                return
        }

        g, ctx := errgroup.WithContext(context.Background())

        // Loop over the array of files passed in and delete them. If any of the file deletions
        // fail just abort the process entirely.
        for _, p := range data.Files {
                pi := path.Join(data.Root, p)

                g.Go(func() error {
                        select {
                        case <-ctx.Done():
                                return ctx.Err()
                        default:
                                if err := s.Filesystem().IsIgnored(pi); err != nil {
                                        return err
                                }
                                return s.Filesystem().Delete(pi)
                        }
                })
        }

        if err := g.Wait(); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }

        c.Status(http.StatusNoContent)
}

// Writes the contents of the request to a file on a server.
func postServerWriteFile(c *gin.Context) {
        s := middleware.ExtractServer(c)

        f := c.Query("file")
        f = "/" + strings.TrimLeft(f, "/")

        if err := s.Filesystem().IsIgnored(f); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }

        // A content length of -1 means the actual length is unknown.
        if c.Request.ContentLength == -1 {
                c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                        "error": "Missing Content-Length",
                })
                return
        }

        if err := s.Filesystem().Write(f, c.Request.Body, c.Request.ContentLength, 0o644); err != nil {
                if filesystem.IsErrorCode(err, filesystem.ErrCodeIsDirectory) {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "Cannot write file, name conflicts with an existing directory by the same name.",
                        })
                        return
                }

                middleware.CaptureAndAbort(c, err)
                return
        }

        c.Status(http.StatusNoContent)
}

// Returns all of the currently in-progress file downloads and their current download
// progress. The progress is also pushed out via a websocket event allowing you to just
// call this once to get current downloads, and then listen to targeted websocket events
// with the current progress for everything.
func getServerPullingFiles(c *gin.Context) {
        s := middleware.ExtractServer(c)
        c.JSON(http.StatusOK, gin.H{
                "downloads": downloader.ByServer(s.ID()),
        })
}

// Writes the contents of the remote URL to a file on a server.
func postServerPullRemoteFile(c *gin.Context) {
        s := middleware.ExtractServer(c)
        var data struct {
                // Deprecated
                Directory  string `binding:"required_without=RootPath,omitempty" json:"directory"`
                RootPath   string `binding:"required_without=Directory,omitempty" json:"root"`
                URL        string `binding:"required" json:"url"`
                FileName   string `json:"file_name"`
                UseHeader  bool   `json:"use_header"`
                Foreground bool   `json:"foreground"`
        }
        if err := c.BindJSON(&data); err != nil {
                return
        }

        // Handle the deprecated Directory field in the struct until it is removed.
        if data.Directory != "" && data.RootPath == "" {
                data.RootPath = data.Directory
        }

        u, err := url.Parse(data.URL)
        if err != nil {
                if e, ok := err.(*url.Error); ok {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "An error occurred while parsing that URL: " + e.Err.Error(),
                        })
                        return
                }
                middleware.CaptureAndAbort(c, err)
                return
        }

        if err := s.Filesystem().HasSpaceErr(true); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }
        // Do not allow more than three simultaneous remote file downloads at one time.
        if len(downloader.ByServer(s.ID())) >= 3 {
                c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                        "error": "This server has reached its limit of 3 simultaneous remote file downloads at once. Please wait for one to complete before trying again.",
                })
                return
        }

        dl := downloader.New(s, downloader.DownloadRequest{
                Directory: data.RootPath,
                URL:       u,
                FileName:  data.FileName,
                UseHeader: data.UseHeader,
        })
        if err := s.Filesystem().IsIgnored(dl.Path()); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }
        download := func() error {
                s.Log().WithField("download_id", dl.Identifier).WithField("url", u.String()).Info("starting pull of remote file to disk")
                if err := dl.Execute(); err != nil {
                        s.Log().WithField("download_id", dl.Identifier).WithField("error", err).Error("failed to pull remote file")
                        return err
                } else {
                        s.Log().WithField("download_id", dl.Identifier).Info("completed pull of remote file")
                }
                return nil
        }
        if !data.Foreground {
                go func() {
                        _ = download()
                }()
                c.JSON(http.StatusAccepted, gin.H{
                        "identifier": dl.Identifier,
                })
                return
        }

        if err := download(); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }

        st, err := s.Filesystem().Stat(dl.Path())
        if err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }
        c.JSON(http.StatusOK, &st)
}

// Stops a remote file download if it exists and belongs to this server.
func deleteServerPullRemoteFile(c *gin.Context) {
        s := middleware.ExtractServer(c)
        if dl := downloader.ByID(c.Param("download")); dl != nil && dl.BelongsTo(s) {
                dl.Cancel()
        }
        c.Status(http.StatusNoContent)
}
 
// Create a directory on a server.
func postServerCreateDirectory(c *gin.Context) {
        s := middleware.ExtractServer(c)

        var data struct {
                Name string `json:"name"`
                Path string `json:"path"`
        }
        // BindJSON sends 400 if the request fails, all we need to do is return
        if err := c.BindJSON(&data); err != nil {
                return
        }

        if err := s.Filesystem().CreateDirectory(data.Name, data.Path); err != nil {
                if errors.Is(err, ufs.ErrNotDirectory) {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "Part of the path being created is not a directory (ENOTDIR).",
                        })
                        return
                }
                if errors.Is(err, os.ErrExist) {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "Cannot create directory, name conflicts with an existing file by the same name.",
                        })
                        return
                }

                middleware.CaptureAndAbort(c, err)
                return
        }

        c.Status(http.StatusNoContent)
}

func postServerCompressFiles(c *gin.Context) {
        s := middleware.ExtractServer(c)

        var data struct {
                RootPath string   `json:"root"`
                Files    []string `json:"files"`
                Name     string   `json:"name"`
        }

        if err := c.BindJSON(&data); err != nil {
                return
        }

        if len(data.Files) == 0 {
                c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
                        "error": "No files were passed through to be compressed.",
                })
                return
        }

        if !s.Filesystem().HasSpaceAvailable(true) {
                c.AbortWithStatusJSON(http.StatusConflict, gin.H{
                        "error": "This server does not have enough available disk space to generate a compressed archive.",
                })
                return
        }

        f, err := s.Filesystem().CompressFiles(data.RootPath, data.Name, data.Files)
        if err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }

        c.JSON(http.StatusOK, &filesystem.Stat{
                FileInfo: f,
                Mimetype: "application/tar+gzip",
        })
}

// postServerDecompressFiles receives the HTTP request and starts the process
// of unpacking an archive that exists on the server into the provided RootPath
// for the server.
func postServerDecompressFiles(c *gin.Context) {
        var data struct {
                RootPath string `json:"root"`
                File     string `json:"file"`
        }
        if err := c.BindJSON(&data); err != nil {
                return
        }

        s := middleware.ExtractServer(c)
        lg := middleware.ExtractLogger(c).WithFields(log.Fields{"root_path": data.RootPath, "file": data.File})
        lg.Debug("checking if space is available for file decompression")
        err := s.Filesystem().SpaceAvailableForDecompression(context.Background(), data.RootPath, data.File)
        if err != nil {
                if filesystem.IsErrorCode(err, filesystem.ErrCodeUnknownArchive) {
                        lg.WithField("error", err).Warn("failed to decompress file: unknown archive format")
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The archive provided is in a format Wings does not understand."})
                        return
                }
                middleware.CaptureAndAbort(c, err)
                return
        }

        lg.Info("starting file decompression")
        if err := s.Filesystem().DecompressFile(context.Background(), data.RootPath, data.File); err != nil {
                // If the file is busy for some reason just return a nicer error to the user since there is not
                // much we specifically can do. They'll need to stop the running server process in order to overwrite
                // a file like this.
                if strings.Contains(err.Error(), "text file busy") {
                        lg.WithField("error", errors.WithStackIf(err)).Warn("failed to decompress file: text file busy")
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "One or more files this archive is attempting to overwrite are currently in use by another process. Please try again.",
                        })
                        return
                }
                middleware.CaptureAndAbort(c, err)
                return
        }
        c.Status(http.StatusNoContent)
}

type chmodFile struct {
        File string `json:"file"`
        Mode string `json:"mode"`
}

var errInvalidFileMode = errors.New("invalid file mode")

func postServerChmodFile(c *gin.Context) {
        s := middleware.ExtractServer(c)

        var data struct {
                Root  string      `json:"root"`
                Files []chmodFile `json:"files"`
        }

        if err := c.BindJSON(&data); err != nil {
                log.Debug(err.Error())
                return
        }

        if len(data.Files) == 0 {
                c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
                        "error": "No files to chmod were provided.",
                })
                return
        }

        g, ctx := errgroup.WithContext(context.Background())

        // Loop over the array of files passed in and perform the move or rename action against each.
        for _, p := range data.Files {
                g.Go(func() error {
                        select {
                        case <-ctx.Done():
                                return ctx.Err()
                        default:
                                mode, err := strconv.ParseUint(p.Mode, 8, 32)
                                if err != nil {
                                        return errInvalidFileMode
                                }

                                if err := s.Filesystem().Chmod(path.Join(data.Root, p.File), os.FileMode(mode)); err != nil {
                                        // Return nil if the error is an is not exists.
                                        // NOTE: os.IsNotExist() does not work if the error is wrapped.
                                        if errors.Is(err, os.ErrNotExist) {
                                                return nil
                                        }

                                        return err
                                }

                                return nil
                        }
                })
        }

        if err := g.Wait(); err != nil {
                if errors.Is(err, errInvalidFileMode) {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "Invalid file mode.",
                        })
                        return
                }

                middleware.CaptureAndAbort(c, err)
                return
        }

        c.Status(http.StatusNoContent)
}

func postServerUploadFiles(c *gin.Context) {
        manager := middleware.ExtractManager(c)

        token := tokens.UploadPayload{}
        if err := tokens.ParseToken([]byte(c.Query("token")), &token); err != nil {
                middleware.CaptureAndAbort(c, err)
                return
        }

        s, ok := manager.Get(token.ServerUuid)
        if !ok || !token.IsUniqueRequest() {
                c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
                        "error": "The requested resource was not found on this server.",
                })
                return
        }

        form, err := c.MultipartForm()
        if err != nil {
                c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                        "error": "Failed to get multipart form data from request.",
                })
                return
        }

        headers, ok := form.File["files"]
        if !ok {
                c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                        "error": "No files were found on the request body.",
                })
                return
        }

        directory := c.Query("directory")

        maxFileSize := config.Get().Api.UploadLimit
        maxFileSizeBytes := maxFileSize * 1024 * 1024
        var totalSize int64
        for _, header := range headers {
                if header.Size > maxFileSizeBytes {
                        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                                "error": "File " + header.Filename + " is larger than the maximum file upload size of " + strconv.FormatInt(maxFileSize, 10) + " MB.",
                        })
                        return
                }
                totalSize += header.Size
        }

        for _, header := range headers {
                // We run this in a different method so I can use defer without any of
                // the consequences caused by calling it in a loop.
                if err := handleFileUpload(filepath.Join(directory, header.Filename), s, header); err != nil {
                        middleware.CaptureAndAbort(c, err)
                        return
                } else {
                        s.SaveActivity(s.NewRequestActivity(token.UserUuid, c.ClientIP()), server.ActivityFileUploaded, models.ActivityMeta{
                                "file":      header.Filename,
                                "directory": filepath.Clean(directory),
                        })
                }
        }
}

func handleFileUpload(p string, s *server.Server, header *multipart.FileHeader) error {
        file, err := header.Open()
        if err != nil {
                return err
        }
        defer file.Close()

        if err := s.Filesystem().IsIgnored(p); err != nil {
                return err
        }

        if err := s.Filesystem().Write(p, file, header.Size, 0o644); err != nil {
                return err
        }
        return nil
}