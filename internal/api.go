package internal

type AddPeerReq struct {
	Key []byte
}

type AddPeerResp struct {
	Key      []byte
	Endpoint string
}
