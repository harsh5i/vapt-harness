package sample

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequest("GET", r.URL.Query().Get("next"), nil)
	http.DefaultClient.Do(req)
	cmd := exec.Command("sh", "-c", r.URL.Query().Get("cmd"))
	cmd.Run()
}

func publish(userID string) {
	event := NewWebSocketEvent("secret_update", "", userID, nil)
	Publish(event)
}
