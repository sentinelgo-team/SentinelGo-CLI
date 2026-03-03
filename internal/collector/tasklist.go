type ProcessInfo struct {
    Name        string `json:"name"`
    PID         int    `json:"pid"`
    SessionName string `json:"session_name"`
    SessionID   int    `json:"session_id"`
    MemoryUsage string `json:"memory_usage"`
}
