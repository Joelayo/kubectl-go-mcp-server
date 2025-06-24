package kubectl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"kubectl-go-mcp-server/internal/config"
	"kubectl-go-mcp-server/pkg/types"
)

type KubectlTool struct{}

func (t *KubectlTool) Name() string {
	return "kubectl"
}

func (t *KubectlTool) Description() string {
	return `Execute kubectl commands to interact with your Kubernetes cluster. Use this tool to query cluster state, manage resources, and perform administrative tasks.

Note: Interactive commands (kubectl exec -it, kubectl edit, kubectl port-forward) are not supported. Use non-interactive alternatives instead.

Examples: kubectl get pods, kubectl describe deployment my-app, kubectl logs my-pod, kubectl exec my-pod -- ps aux`
}

func (t *KubectlTool) FunctionDefinition() *types.FunctionDefinition {
	return &types.FunctionDefinition{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &types.Schema{
			Type: types.TypeObject,
			Properties: map[string]*types.Schema{"command": {
				Type: types.TypeString,
				Description: `The complete kubectl command to execute (include 'kubectl' prefix).

Examples:
• kubectl get pods
• kubectl describe deployment my-app  
• kubectl logs my-pod --tail=50
• kubectl exec my-pod -- ps aux

Note: Interactive commands (exec -it, edit, port-forward) are not supported.`,
			}, "modifies_resource": {
				Type:        types.TypeString,
				Description: `Whether the command modifies cluster resources: "yes", "no", or "unknown"`,
			},
			},
			Required: []string{"command"},
		},
	}
}

func (t *KubectlTool) Run(ctx context.Context, args map[string]any) (any, error) {
	kubeconfigVal := ctx.Value(types.KubeconfigKey)
	if kubeconfigVal == nil {
		return &types.ExecResult{Error: "kubeconfig not provided in context"}, nil
	}
	kubeconfig, ok := kubeconfigVal.(string)
	if !ok {
		return &types.ExecResult{Error: "kubeconfig must be a string"}, nil
	}

	workDirVal := ctx.Value(types.WorkdirKey)
	if workDirVal == nil {
		return &types.ExecResult{Error: "workdir not provided in context"}, nil
	}
	workDir, ok := workDirVal.(string)
	if !ok {
		return &types.ExecResult{Error: "workdir must be a string"}, nil
	}

	commandVal, ok := args["command"]
	if !ok || commandVal == nil {
		return &types.ExecResult{Error: "kubectl command not provided or is nil"}, nil
	}

	command, ok := commandVal.(string)
	if !ok {
		return &types.ExecResult{Error: "kubectl command must be a string"}, nil
	}

	if err := ValidateKubectlCommand(command); err != nil {
		return &types.ExecResult{Error: fmt.Sprintf("Security violation: %s", err.Error())}, nil
	}

	return RunKubectlCommand(ctx, command, workDir, kubeconfig)
}

func (t *KubectlTool) IsInteractive(args map[string]any) (bool, error) {
	commandVal, ok := args["command"]
	if !ok || commandVal == nil {
		return false, nil
	}

	command, ok := commandVal.(string)
	if !ok {
		return false, nil
	}

	return IsInteractiveCommand(command)
}

func (t *KubectlTool) CheckModifiesResource(args map[string]any) string {
	command, ok := args["command"].(string)
	if !ok {
		return "unknown"
	}

	return ModifiesResource(command)
}

func ValidateKubectlCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command cannot be empty")
	}

	words := strings.Fields(strings.TrimSpace(command))
	if len(words) == 0 {
		return fmt.Errorf("command cannot be empty")
	}

	firstWord := words[0]
	baseName := filepath.Base(firstWord)
	if baseName != "kubectl" {
		return fmt.Errorf("only kubectl commands are allowed, got: %s", baseName)
	}

	if err := checkForCommandInjection(command); err != nil {
		return err
	}

	if len(words) < 2 {
		return fmt.Errorf("kubectl command must include a subcommand (e.g., 'kubectl get pods')")
	}

	subcommand := words[1]
	if !isValidKubectlSubcommand(subcommand) {
		return fmt.Errorf("invalid or restricted kubectl subcommand: %s", subcommand)
	}

	return nil
}

func checkForCommandInjection(command string) error {
	dangerousPatterns := []string{
		";", "&&", "||", "|", "`", "$(",
		"$(", "${", ">/", "<", ">>", "<<",
		"&", "\n", "\r", "curl", "wget", "nc",
		"netcat", "rm ", "mv ",
		"cp ", "chmod", "chown", "sudo", "su ",
	}

	lowerCommand := strings.ToLower(command)

	if strings.Contains(lowerCommand, "kubectl exec") && strings.Contains(lowerCommand, " -- ") {
		parts := strings.Split(lowerCommand, " -- ")
		if len(parts) > 0 {
			execPart := parts[0]
			for _, pattern := range dangerousPatterns {
				if strings.Contains(execPart, pattern) {
					return fmt.Errorf("command contains potentially dangerous pattern: %s", pattern)
				}
			}
			if len(parts) > 1 {
				afterDoubleDash := parts[1]
				strictPatterns := []string{
					";", "&&", "||", "|", "`", "$(",
					"$(", "${", ">/", "<", ">>", "<<",
					"&", "\n", "\r", "curl", "wget", "nc",
					"netcat", "rm ", "mv ", "cp ", "chmod", "chown", "sudo", "su ",
				}
				for _, pattern := range strictPatterns {
					if strings.Contains(afterDoubleDash, pattern) {
						return fmt.Errorf("command contains potentially dangerous pattern: %s", pattern)
					}
				}
			}
			return nil
		}
	}

	allPatterns := append(dangerousPatterns, "bash", "sh", "/bin/", "python", "perl", "ruby")
	for _, pattern := range allPatterns {
		if strings.Contains(lowerCommand, pattern) {
			return fmt.Errorf("command contains potentially dangerous pattern: %s", pattern)
		}
	}

	return nil
}

func isValidKubectlSubcommand(subcommand string) bool {
	allowedSubcommands := map[string]bool{
		"get":      true,
		"describe": true,
		"logs":     true,
		"exec":     true,
		"top":      true,
		"explain":  true,

		"create":   true,
		"apply":    true,
		"delete":   true,
		"patch":    true,
		"replace":  true,
		"scale":    true,
		"rollout":  true,
		"annotate": true,
		"label":    true,

		"config":        true,
		"cluster-info":  true,
		"version":       true,
		"api-versions":  true,
		"api-resources": true,

		"diff":         true,
		"port-forward": true,
		"proxy":        true,
		"auth":         true,
		"certificate":  true,
		"cordon":       true,
		"uncordon":     true,
		"drain":        true,
		"taint":        true,
		"wait":         true,
	}

	return allowedSubcommands[subcommand]
}

func RunKubectlCommand(ctx context.Context, command, workDir, kubeconfig string) (*types.ExecResult, error) {
	if err := ValidateKubectlCommand(command); err != nil {
		return &types.ExecResult{Error: fmt.Sprintf("Security validation failed: %s", err.Error())}, nil
	}

	if isInteractive, err := IsInteractiveCommand(command); isInteractive {
		return &types.ExecResult{Error: err.Error()}, nil
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, os.Getenv("COMSPEC"), "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, LookupBashBin(), "-c", command)
	}
	cmd.Env = os.Environ()
	cmd.Dir = workDir

	cmd.Env = removeEnvVar(cmd.Env, "KUBECONFIG")

	if kubeconfig != "" {
		expandedKubeconfig, err := config.ValidateKubeconfigPath(kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("invalid kubeconfig path %q: %w", kubeconfig, err)
		}
		cmd.Env = append(cmd.Env, "KUBECONFIG="+expandedKubeconfig)
	}

	return executeCommand(cmd)
}

func IsInteractiveCommand(command string) (bool, error) {
	words := strings.Fields(command)
	if len(words) == 0 {
		return false, nil
	}
	base := filepath.Base(words[0])
	if base != "kubectl" {
		return false, nil
	}

	isExec := strings.Contains(command, " exec ") && strings.Contains(command, " -it")
	isPortForward := strings.Contains(command, " port-forward ")
	isEdit := strings.Contains(command, " edit ")

	if isExec || isPortForward || isEdit {
		return true, fmt.Errorf("interactive mode not supported for kubectl, please use non-interactive commands")
	}
	return false, nil
}

func ModifiesResource(command string) string {
	words := strings.Fields(command)
	if len(words) < 2 {
		return "unknown"
	}

	if filepath.Base(words[0]) != "kubectl" {
		return "unknown"
	}

	verb := words[1]
	switch verb {
	case "get", "describe", "logs", "top", "version", "cluster-info", "config":
		return "no"
	case "create", "apply", "delete", "patch", "replace", "scale", "rollout", "annotate", "label":
		return "yes"
	case "exec", "port-forward", "proxy":
		return "no"
	default:
		return "unknown"
	}
}

func executeCommand(cmd *exec.Cmd) (*types.ExecResult, error) {
	command := strings.Join(cmd.Args, " ")

	if isInteractive, err := IsInteractiveCommand(command); isInteractive {
		return &types.ExecResult{Command: command, Error: err.Error()}, nil
	}

	output, err := cmd.CombinedOutput()
	result := &types.ExecResult{
		Command: command,
		Stdout:  string(output),
	}

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		}
		result.Error = err.Error()
	}

	return result, nil
}

func LookupBashBin() string {
	actualBashPath, err := exec.LookPath("bash")
	if err != nil {
		return "/bin/bash"
	}
	return actualBashPath
}

// Deprecated: Use config.ValidateKubeconfigPath instead for better cross-platform support
func ExpandShellVar(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func removeEnvVar(env []string, key string) []string {
	var result []string
	prefix := key + "="

	for _, envVar := range env {
		if !strings.HasPrefix(envVar, prefix) {
			result = append(result, envVar)
		}
	}

	return result
}
