package tracing

import (
	"context"
	"fmt"
	"unsafe"
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

	go func() {
		<-ctx.Done()
		events.Close()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := events.Read()
				if err != nil {
					log.WithError(err).Warn("failed to read event")
					continue
				}

				event := (*SocketEvent)(unsafe.Pointer(&record.RawSample[0]))
				if event.Type == SocketClose {
					log.Debugf("socket close: %v", event)
				} else {
					var conn ConnInfo
					if err := connMap.Lookup(event.ConnId.TgidFd(), &conn); err != nil {
						log.WithError(err).Warnf("failed to lookup conn id: %d", event.ConnId.TgidFd())
						continue
					}
					raddr := ParseSockaddr(conn.Raddr[:])
					log.Debugf("socket open: %v, raddr: %v", event, raddr)
				}
			}
		}
	}()
	return nil
}
