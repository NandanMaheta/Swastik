package ipomarket

import "github.com/danielgtaylor/huma/v2"

// Register adds the HTTP operations. Operations are added in S17; until then nothing is registered.
func Register(api huma.API, s *Service) {
	registerAdmin(api, s)
	registerClient(api, s)
}

func registerAdmin(huma.API, *Service) {}
