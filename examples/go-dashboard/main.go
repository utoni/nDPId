package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"ui"
)

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger

	NETWORK_BUFFER_MAX_SIZE uint16 = 9216
	nDPIsrvd_JSON_BYTES     uint16 = 4
)

type packet_event struct {
	ThreadID uint8  `json:"thread_id"`
	PacketID uint64 `json:"packet_id"`

	FlowID       uint32 `json:"flow_id"`
	FlowPacketID uint64 `json:"flow_packet_id"`
	MaxPackets   uint8  `json:"max_packets"`

	PacketEventID       uint8  `json:"packet_event_id"`
	PacketEventName     string `json:"packet_event_name"`
	PacketOversize      bool   `json:"pkt_oversize"`
	PacketTimestamp     uint64 `json:"pkt_ts"`
	PacketLength        uint32 `json:"pkt_len"`
	Packet              string `json:"pkt"`
	PacketCaptureLength uint32 `json:"pkt_caplen"`
	PacketType          uint32 `json:"pkt_type"`
	PacketIpOffset      uint32 `json:"pkt_ipoffset"`
}

type flow_event struct {
	ThreadID uint8  `json:"thread_id"`
	PacketID uint64 `json:"packet_id"`

	FlowID                    uint32 `json:"flow_id"`
	FlowPacketID              uint64 `json:"flow_packet_id"`
	FlowFirstSeen             uint64 `json:"flow_first_seen"`
	FlowLastSeen              uint64 `json:"flow_last_seen"`
	FlowTotalLayer4DataLength uint64 `json:"flow_tot_l4_data_len"`
	FlowMinLayer4DataLength   uint64 `json:"flow_min_l4_data_len"`
	FlowMaxLayer4DataLength   uint64 `json:"flow_max_l4_data_len"`
	FlowAvgLayer4DataLength   uint64 `json:"flow_avg_l4_data_len"`
	IsMidstreamFlow           uint32 `json:"midstream"`
}

type basic_event struct {
	ThreadID uint8  `json:"thread_id"`
	PacketID uint64 `json:"packet_id"`

	BasicEventID   uint8  `json:"basic_event_id"`
	BasicEventName string `json:"basic_event_name"`
}

func main() {
	ui.Init()

	InfoLogger = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(os.Stderr, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	conn, err := net.Dial("tcp", "127.0.0.1:7000")
	if err != nil {
		ErrorLogger.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, NETWORK_BUFFER_MAX_SIZE)
	var jsonStr string
	var jsonStrLen uint16 = 0
	var jsonLen uint16 = 0

	rd := bufio.NewReaderSize(conn, int(NETWORK_BUFFER_MAX_SIZE))
	for {
		nread, err := rd.Read(buf)

		if err != nil {
			if err != io.EOF {
				ErrorLogger.Printf("Read Error: %v\n", err)
				break
			}
		}

		if nread == 0 || err == io.EOF {
			WarningLogger.Printf("Disconnect from Server\n")
			break
		}

		jsonStr += string(buf[:nread])
		jsonStrLen += uint16(nread)

		for {
			if jsonStrLen < nDPIsrvd_JSON_BYTES+1 {
				break
			}

			if jsonStr[nDPIsrvd_JSON_BYTES] != '{' {
				ErrorLogger.Printf("BUG: JSON invalid opening character at position %d: '%s' (%x)\n",
					nDPIsrvd_JSON_BYTES,
					string(jsonStr[:nDPIsrvd_JSON_BYTES]), jsonStr[nDPIsrvd_JSON_BYTES])
				os.Exit(1)
			}

			if jsonLen == 0 {
				var tmp uint64
				if tmp, err = strconv.ParseUint(strings.TrimLeft(jsonStr[:4], "0"), 10, 16); err != nil {
					ErrorLogger.Printf("BUG: Could not parse length of a JSON string: %v\n", err)
					os.Exit(1)
				} else {
					jsonLen = uint16(tmp)
				}
			}

			if jsonStrLen < jsonLen+nDPIsrvd_JSON_BYTES {
				break
			}

			if jsonStr[jsonLen+nDPIsrvd_JSON_BYTES-1] != '}' {
				ErrorLogger.Printf("BUG: JSON invalid closing character at position %d: '%s'\n",
					jsonLen+nDPIsrvd_JSON_BYTES,
					string(jsonStr[jsonLen+nDPIsrvd_JSON_BYTES-1]))
				os.Exit(1)
			}

			jsonMap := make(map[string]interface{})
			err := json.Unmarshal([]byte(jsonStr[nDPIsrvd_JSON_BYTES:nDPIsrvd_JSON_BYTES+jsonLen]), &jsonMap)
			if err != nil {
				ErrorLogger.Printf("BUG: JSON error: %v\n", err)
				os.Exit(1)
			}
			if jsonMap["packet_event_id"] != nil {
				pe := packet_event{}
				if err := json.Unmarshal([]byte(jsonStr[nDPIsrvd_JSON_BYTES:nDPIsrvd_JSON_BYTES+jsonLen]), &pe); err != nil {
					ErrorLogger.Printf("BUG: JSON Unmarshal error: %v\n", err)
					os.Exit(1)
				}
				InfoLogger.Printf("PACKET EVENT %v\n", pe)
			} else if jsonMap["flow_event_id"] != nil {
				fe := flow_event{}
				if err := json.Unmarshal([]byte(jsonStr[nDPIsrvd_JSON_BYTES:nDPIsrvd_JSON_BYTES+jsonLen]), &fe); err != nil {
					ErrorLogger.Printf("BUG: JSON Unmarshal error: %v\n", err)
					os.Exit(1)
				}
				InfoLogger.Printf("FLOW EVENT %v\n", fe)
			} else if jsonMap["basic_event_id"] != nil {
				be := basic_event{}
				if err := json.Unmarshal([]byte(jsonStr[nDPIsrvd_JSON_BYTES:nDPIsrvd_JSON_BYTES+jsonLen]), &be); err != nil {
					ErrorLogger.Printf("BUG: JSON Unmarshal error: %v\n", err)
					os.Exit(1)
				}
				InfoLogger.Printf("BASIC EVENT %v\n", be)
			} else {
				ErrorLogger.Printf("BUG: Unknown JSON: %v\n", jsonStr[nDPIsrvd_JSON_BYTES:nDPIsrvd_JSON_BYTES+jsonLen])
				os.Exit(1)
			}
			//InfoLogger.Printf("JSON map: %v\n-------------------------------------------------------\n", jsonMap)

			jsonStr = jsonStr[jsonLen+nDPIsrvd_JSON_BYTES:]
			jsonStrLen -= (jsonLen + nDPIsrvd_JSON_BYTES)
			jsonLen = 0
		}
	}
}
