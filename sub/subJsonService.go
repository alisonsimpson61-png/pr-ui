package sub

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MHSanaei/3x-ui/database/model"
	"github.com/MHSanaei/3x-ui/logger"
	"github.com/MHSanaei/3x-ui/web/service"
	"github.com/MHSanaei/3x-ui/xray"
	"gopkg.in/yaml.v3"
	"github.com/MHSanaei/3x-ui/util/random"
)

type SubClashYAMLService struct {
	fragment      string
	noises        string
	SubService    *SubService
	inboundSvc    service.InboundService
	defaultGroups []map[string]any
}

// 初始化服务
func NewSubClashYAMLService(fragment, noises string, subService *SubService) *SubClashYAMLService {
	return &SubClashYAMLService{
		fragment:   fragment,
		noises:     noises,
		SubService: subService,
		defaultGroups: []map[string]any{
			{
				"name":    "auto",
				"type":    "select",
				"proxies": []string{},
			},
			{
				"name":    "fallback",
				"type":    "select",
				"proxies": []string{},
			},
		},
	}
}

// 生成 OpenClash YAML 订阅
func (s *SubClashYAMLService) GetClashYAML(subId string, host string) (string, string, error) {
	inbounds, err := s.SubService.getInboundsBySubId(subId)
	if err != nil || len(inbounds) == 0 {
		return "", "", err
	}

	var clientTraffics []xray.ClientTraffic
	proxies := []map[string]any{}

	for _, inbound := range inbounds {
		clients, err := s.inboundSvc.GetClients(inbound)
		if err != nil || clients == nil {
			continue
		}

		// Fallback master
		if len(inbound.Listen) > 0 && inbound.Listen[0] == '@' {
			listen, port, streamSettings, err := s.SubService.getFallbackMaster(inbound.Listen, inbound.StreamSettings)
			if err == nil {
				inbound.Listen = listen
				inbound.Port = port
				inbound.StreamSettings = streamSettings
			}
		}

		for _, client := range clients {
			if client.Enable && client.SubID == subId {
				clientTraffics = append(clientTraffics, s.SubService.getClientTraffics(inbound.ClientStats, client.Email))
				proxies = append(proxies, s.genClashProxy(inbound, client, host)...)
			}
		}
	}

	if len(proxies) == 0 {
		return "", "", nil
	}

	// 累加流量统计
	var traffic xray.ClientTraffic
	for i, cTraffic := range clientTraffics {
		if i == 0 {
			traffic = cTraffic
		} else {
			traffic.Up += cTraffic.Up
			traffic.Down += cTraffic.Down
			if traffic.Total == 0 || cTraffic.Total == 0 {
				traffic.Total = 0
			} else {
				traffic.Total += cTraffic.Total
			}
			if cTraffic.ExpiryTime != traffic.ExpiryTime {
				traffic.ExpiryTime = 0
			}
		}
	}

	// 填充 proxy-groups 中的 proxies
	for _, group := range s.defaultGroups {
		if list, ok := group["proxies"].([]string); ok {
			for _, p := range proxies {
				list = append(list, p["name"].(string))
			}
			group["proxies"] = list
		}
	}

	// 自动生成常用规则，可根据实际情况扩展
	rules := []any{
		"DOMAIN-SUFFIX,google.com,auto",
		"DOMAIN-SUFFIX,github.com,auto",
		"DOMAIN-KEYWORD,youtube,auto",
		"DOMAIN-SUFFIX,twitch.tv,auto",
		"FINAL,auto",
	}

	// 生成 YAML
	yamlMap := map[string]any{
		"proxies":      proxies,
		"proxy-groups": s.defaultGroups,
		"rules":        rules,
	}

	yamlBytes, err := yaml.Marshal(yamlMap)
	if err != nil {
		logger.Error("Failed to marshal YAML: %v", err)
		return "", "", err
	}

	header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)

	return string(yamlBytes), header, nil
}

// 生成 Clash 风格 proxies
func (s *SubClashYAMLService) genClashProxy(inbound *model.Inbound, client model.Client, host string) []map[string]any {
	stream := map[string]any{}
	_ = json.Unmarshal([]byte(inbound.StreamSettings), &stream)

	proxies := []map[string]any{}

	externalProxies, ok := stream["externalProxy"].([]any)
	if !ok || len(externalProxies) == 0 {
		externalProxies = []any{
			map[string]any{
				"dest": host,
				"port": float64(inbound.Port),
			},
		}
	}

	for _, ep := range externalProxies {
		extPrxy, ok := ep.(map[string]any)
		if !ok { continue }

		p := map[string]any{
			"name":   fmt.Sprintf("%s-%s", client.Email, extPrxy["dest"].(string)),
			"server": extPrxy["dest"].(string),
			"port":   int(extPrxy["port"].(float64)),
		}

		// 协议类型
		switch inbound.Protocol {
		case model.VMESS:
			p["type"] = "vmess"
			p["uuid"] = client.ID
			p["alterId"] = 0
			p["cipher"] = client.Security
		case model.VLESS:
			p["type"] = "vless"
			p["uuid"] = client.ID
			p["encryption"] = "none"
		case model.Trojan:
			p["type"] = "trojan"
			p["password"] = client.Password
		case model.Shadowsocks:
			p["type"] = "ss"
			p["password"] = client.Password
			var inboundSettings map[string]any
			_ = json.Unmarshal([]byte(inbound.Settings), &inboundSettings)
			if method, ok := inboundSettings["method"].(string); ok {
				p["cipher"] = method
			}
		}

		// 网络类型
		if network, ok := stream["network"].(string); ok {
			p["network"] = network
			switch network {
			case "ws":
				if wsPath, ok := stream["ws-path"].(string); ok {
					p["ws-path"] = wsPath
				}
				if wsHeader, ok := stream["ws-headers"].(map[string]any); ok {
					p["ws-headers"] = wsHeader
				}
			case "http":
				if headers, ok := stream["http-headers"].(map[string]any); ok {
					p["http-headers"] = headers
				}
			}
		}

		// TLS/Reality
		if security, ok := stream["security"].(string); ok {
			if security == "tls" {
				p["tls"] = true
				if s.fragment != "" {
					p["skip-cert-verify"] = true
				}
			} else if security == "reality" {
				p["tls"] = true
				if pk, ok := stream["publicKey"].(string); ok {
					p["publicKey"] = pk
				}
				if fp, ok := stream["fingerprint"].(string); ok {
					p["fingerprint"] = fp
				}
				if sid, ok := stream["shortId"].(string); ok {
					p["shortId"] = sid
				} else {
					p["shortId"] = random.Seq(8)
				}
			}
		}

		proxies = append(proxies, p)
	}

	return proxies
}
