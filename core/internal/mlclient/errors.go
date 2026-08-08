package mlclient

import "errors"

var (
	errCircuitOpen = errors.New("mlclient: circuit breaker open")
	errMLStatus    = errors.New("mlclient: non-200 from ML service")
)
