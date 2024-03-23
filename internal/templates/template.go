package templates

import (
	"encoding/json"
	"fmt"
)

func ParseTemplateData(data string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(data), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template data: %w", err)
	}
	return result, nil
}
