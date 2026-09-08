package openwrt

import (
	"encoding/json"
	"errors"
)

// ServiceObservation is the typed subset of ubus service.list needed by
// capability health. Presence and running are separate so a declared but
// stopped service cannot be reported as healthy.
type ServiceObservation struct {
	Present   bool
	Running   bool
	Instances int
}

func ParseServiceList(data []byte) (map[string]ServiceObservation, error) {
	var services map[string]json.RawMessage
	if err := json.Unmarshal(data, &services); err != nil || services == nil {
		return nil, errors.New("provider service list is malformed")
	}
	result := make(map[string]ServiceObservation, len(services))
	for name, raw := range services {
		observation := ServiceObservation{Present: true}
		observation.Instances, observation.Running = serviceInstances(raw)
		result[name] = observation
	}
	return result, nil
}

func serviceInstances(raw json.RawMessage) (int, bool) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return 0, false
	}
	return serviceInstancesValue(value)
}

func serviceInstancesValue(value any) (int, bool) {
	switch typed := value.(type) {
	case map[string]any:
		instances, running := 0, false
		if value, ok := typed["running"].(bool); ok {
			instances = 1
			running = value
		}
		for key, child := range typed {
			if key == "running" {
				continue
			}
			childInstances, childRunning := serviceInstancesValue(child)
			instances += childInstances
			running = running || childRunning
		}
		return instances, running
	case []any:
		instances, running := 0, false
		for _, child := range typed {
			childInstances, childRunning := serviceInstancesValue(child)
			instances += childInstances
			running = running || childRunning
		}
		return instances, running
	default:
		return 0, false
	}
}
