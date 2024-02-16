package tracing

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/samber/lo"
	"github.com/vietanhduong/wbpf"
)

func (c *Client) runSocketEventHandler(ctx context.Context) error {
	events := c.mod.GetRingBuffer("socket_events")
	if events == nil {
		return fmt.Errorf("failed to get ring buffer: socket_events")
	}

	connMap, err := c.mod.GetTable("conn_map")
	if err != nil {
		return fmt.Errorf("failed to get table: conn_map: %w", err)
	}
	log.Infof("Start socket events handler...")
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Infof("Stop socket events handler...")
				return
			default:
				record, err := events.Read()
				if err != nil {
					continue
				}

				event := (*SocketEvent)(unsafe.Pointer(&record.RawSample[0]))
				if !lo.Contains(c.targetPids, event.ConnId.Pid) {
					continue
				}
				log.Debugf("new event: %v", event)
				log.Debugf("map size: %d", mapSize(connMap))
				if event.Type == SocketOpen {
					var b []byte
					if err := connMap.Lookup(event.ConnId.TgidFd(), &b); err != nil {
						log.WithError(err).Warnf("failed to lookup conn id: %d", event.ConnId.TgidFd())
						continue
					}
					conn := (*ConnInfo)(unsafe.Pointer(&b[0]))
					log.Debugf("Raw: %v", conn.Raddr)
					raddr := ParseSockaddr(conn.Raddr[:])
					log.Debugf("socket open: %v, raddr: %v", event, raddr)
				}
			}
		}
	}()
	return nil
}

func mapSize(m *wbpf.Table) int {
	it := m.Iterate()
	var count int
	var key uint64
	var val []byte
	for it.Next(&key, &val) {
		count++
	}

	return count
}
