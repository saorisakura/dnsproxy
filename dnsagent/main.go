package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/bluele/gcache"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type DNSGuardAPI struct {
	BaseUrl   string
	AgentIp   string
	AgentKey  string
	Headers   map[string]string
	RedisHost string
	RedisPort int
	RedisDB   int
}

func readConfig(filename string) (map[string]interface{}, error) {
	// Read the YAML file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Unmarshal the YAML content into a map
	var result map[string]interface{}
	err = yaml.Unmarshal(content, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func NewDNSGuardAPI(filename string) *DNSGuardAPI {
	config, err := readConfig(filename)
	if err != nil {
		logrus.Errorln("Error reading config file:", err)
		return nil
	}
	dnsGuard := config["dnsguard"].(map[string]interface{})
	agent := config["agent"].(map[string]interface{})
	redisConfig := config["redis"].(map[string]interface{})
	return &DNSGuardAPI{
		BaseUrl:   dnsGuard["api_url"].(string),
		AgentIp:   agent["ip"].(string),
		AgentKey:  agent["key"].(string),
		Headers:   map[string]string{},
		RedisHost: redisConfig["host"].(string),
		RedisPort: redisConfig["port"].(int),
		RedisDB:   redisConfig["db"].(int),
	}
}

func (d *DNSGuardAPI) GetRedis() *redis.Client {
	r := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	if err := r.Ping(r.Context()).Err(); err != nil {
		logrus.Errorln("Error pinging Redis:", err)
	}
	return r
}

func (d *DNSGuardAPI) GetSign() map[string]interface{} {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := fmt.Sprintf("%s%s%s", d.AgentIp, timestamp, d.AgentKey)
	h := md5.New()
	h.Write([]byte(signature))
	signature = fmt.Sprintf("%x", h.Sum(nil))

	return map[string]interface{}{
		"timestamp": timestamp,
		"signature": signature,
		"agent_ip":  d.AgentIp,
	}
}

func (d *DNSGuardAPI) FetchAgentData(ctx context.Context) map[string]interface{} {
	// https://dnsguard.funplus.com.cn/api/v1/app/agent/fetch_data/
	params := d.GetSign()
	action := ctx.Value("action")
	if action != nil {
		params["action"] = action
	}
	// 发起请求
	u, err := url.Parse(d.BaseUrl + "app/agent/fetch_data/")
	if err != nil {
		logrus.Errorln("Error parsing url:", err)
		return nil
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, fmt.Sprintf("%v", v))
	}
	u.RawQuery = q.Encode()
	logrus.Debugln("Request url:", u.String())
	resp, err := http.Get(u.String())
	if err != nil {
		logrus.Errorln("Error fetching agent data:", err)
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorln("Error reading response body:", err)
		return nil
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		logrus.Errorln("Error unmarshalling data:", err)
		return nil
	}
	return data
}

func (d *DNSGuardAPI) PushMetrics(data map[string]interface{}) {
	// TODO,https://dnsguard.funplus.com.cn/api/v1/app/agent/push_metrics/
	params := d.GetSign()
	// 发起请求
	u, err := url.Parse(d.BaseUrl + "app/agent/push_metrics/")
	if err != nil {
		logrus.Errorln("Error parsing url:", err)
		return
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, fmt.Sprintf("%v", v))
	}
	u.RawQuery = q.Encode()
	logrus.Debugln("Request url:", u.String())
	postData := map[string]interface{}{
		"metrics": data,
	}
	logrus.Infoln("Post data:", postData)
	jsonData, err := json.Marshal(postData)
	if err != nil {
		logrus.Errorln("Error marshalling data:", err)
		return
	}

	req, err := http.NewRequest("POST", u.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		logrus.Errorln("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorln("Error pushing metrics:", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorln("Error reading response body:", err)
		return
	}
	logrus.Infoln("Response body:", string(body))
}

type Proxy struct {
	Listener                   *net.UDPConn
	Cache                      gcache.Cache
	CacheDomain                map[string]interface{}
	Api                        *DNSGuardAPI
	DefaultDNS                 []string
	Lock                       *sync.RWMutex
	MetricLock                 *sync.RWMutex
	QueryMetrics               *sync.Map
	DomainQueryMetrics         *sync.Map
	IpQueryMetrics             *sync.Map
	HijackQueryMetrics         *sync.Map
	MatchRecursionQueryMetrics *sync.Map
}

func (p *Proxy) ClearSyncMap() {
	p.MetricLock.Lock()
	defer p.MetricLock.Unlock()
	p.QueryMetrics = &sync.Map{}
	p.DomainQueryMetrics = &sync.Map{}
	p.IpQueryMetrics = &sync.Map{}
	p.HijackQueryMetrics = &sync.Map{}
	p.MatchRecursionQueryMetrics = &sync.Map{}
}

func (p *Proxy) IncrSyncMap(m *sync.Map, key string) {
	p.MetricLock.Lock()
	defer p.MetricLock.Unlock()
	if v, ok := m.Load(key); ok {
		m.Store(key, v.(int)+1)
	} else {
		m.Store(key, 1)
	}
}

func (p *Proxy) ServeDNS(c chan error) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in fetchAgentData: %v", r)
			c <- errors.New(fmt.Sprintf("%v", r))
		}
	}()

	buf := make([]byte, 65535)
	p.Listener.SetReadBuffer(65535)
	p.Listener.SetWriteBuffer(65535)
	for {
		n, remoteAddr, err := p.Listener.ReadFromUDP(buf)
		//n, _, remoteAddr, err := proxynetutil.UDPRead(p.Listener, buf, 32)
		if n > 0 {
			// Make a copy of all bytes because ReadFrom() will overwrite the
			// contents of b on the next call.  We need that contents to sustain
			// the call because we're handling them in goroutines.
			packet := make([]byte, n)
			copy(packet, buf)

			go func() {
				req := &dns.Msg{}
				err = req.Unpack(packet)
				if err != nil {
					logrus.Errorln("unpacking udp packet: %w", err)
					return
				}
				if req.Response {
					logrus.Println("dropping incoming response packet", "addr", remoteAddr)
					return
				}
				resp := p.validateRequest(req)
				if resp == nil {
					resp = p.replyFromProxy(req, remoteAddr)
					if resp == nil {
						resp = p.reply(req, dns.RcodeServerFailure)
						const maxUDPPayload = 1452
						resp.SetEdns0(maxUDPPayload, false)
					}
					response, err := resp.Pack()
					if err != nil {
						logrus.Errorln("packing message: ", err.Error())
						return
					}
					_, err = p.Listener.WriteToUDP(response, remoteAddr)
					if err != nil {
						logrus.Errorln("writing message: ", err.Error())
						return
					}
					logrus.Infoln("response sent", "addr", remoteAddr)
				}
				logrus.Infoln("response sent nil", "addr", remoteAddr)
			}()
		}

		if err != nil {
			logrus.Errorln("reading from udp: ", err, remoteAddr)
			// 关闭客户端连接
		}
	}
}

func (p *Proxy) validateRequest(req *dns.Msg) (resp *dns.Msg) {
	switch {
	case len(req.Question) != 1:
		logrus.Println("invalid number of questions", "req_questions_len", len(req.Question))
		return p.reply(req, dns.RcodeServerFailure)
	case req.Question[0].Qtype == dns.TypeANY:
		logrus.Println("refusing dns type any request")
		resp = p.reply(req, dns.RcodeNotImplemented)
		const maxUDPPayload = 1452
		resp.SetEdns0(maxUDPPayload, false)
		return resp
	default:
		return nil
	}
}

func (p *Proxy) reply(req *dns.Msg, code int) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, code)
	resp.RecursionAvailable = true
	return resp
}

func (p *Proxy) replyFromCache(req *dns.Msg, queryDomain string) *dns.Msg {
	val, err := p.Cache.Get(queryDomain)
	if err != nil {
		return nil
	}
	if val == nil {
		return nil
	}
	p.IncrSyncMap(p.QueryMetrics, "hijack")
	p.IncrSyncMap(p.HijackQueryMetrics, queryDomain)
	if record, ok := val.(map[string]interface{}); ok {
		if record["type"] == "A" {
			logrus.Debugln("replying from cache", "query domain", queryDomain)
			resp := &dns.Msg{}
			resp.SetReply(req)
			resp.Authoritative = true
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   queryDomain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(record["value"].(string)),
			}
			resp.Answer = append(resp.Answer, rr)
			return resp
		} else if record["type"] == "CNAME" {
			// TODO, CNAME类型需要继续查询直到遇到A记录或者查无此记录
			logrus.Debugln("replying from cache", "query domain", queryDomain)
			resp := &dns.Msg{}
			resp.SetReply(req)
			resp.Authoritative = true
			rr := &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   queryDomain,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: record["value"].(string),
			}
			resp.Answer = append(resp.Answer, rr)

			cnameQueryDomain := record["value"].(string)
			cnameQueryMsg := &dns.Msg{}
			cnameQueryMsg.SetQuestion(cnameQueryDomain, dns.TypeA)
			cnameResp := p.replyFromProxy(cnameQueryMsg, nil)
			if cnameResp != nil {
				if cnameResp.Answer != nil {
					resp.Answer = append(resp.Answer, cnameResp.Answer...)
				}
			}
			return resp
		}
	}
	return nil
}

func (p *Proxy) replyFromCacher(r *redis.Client, req *dns.Msg, queryDomain string) *dns.Msg {
	val, err := p.Cache.Get(queryDomain)
	if err != nil {
		return nil
	}
	if val == nil {
		return nil
	}
	setMetrics(r, "total", "hijack")
	setMetrics(r, "hijack", queryDomain)
	if record, ok := val.(map[string]interface{}); ok {
		if record["type"] == "A" {
			logrus.Debugln("replying from cache", "query domain", queryDomain)
			resp := &dns.Msg{}
			resp.SetReply(req)
			resp.Authoritative = true
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   queryDomain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(record["value"].(string)),
			}
			resp.Answer = append(resp.Answer, rr)
			return resp
		} else if record["type"] == "CNAME" {
			// TODO, CNAME类型需要继续查询直到遇到A记录或者查无此记录
			logrus.Debugln("replying from cache", "query domain", queryDomain)
			resp := &dns.Msg{}
			resp.SetReply(req)
			resp.Authoritative = true
			rr := &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   queryDomain,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: record["value"].(string),
			}
			resp.Answer = append(resp.Answer, rr)

			cnameQueryDomain := record["value"].(string)
			cnameQueryMsg := &dns.Msg{}
			cnameQueryMsg.SetQuestion(cnameQueryDomain, dns.TypeA)
			cnameResp := p.replyFromProxy(cnameQueryMsg, nil)
			if cnameResp != nil {
				if cnameResp.Answer != nil {
					resp.Answer = append(resp.Answer, cnameResp.Answer...)
				}
			}
			return resp
		}
	}
	return nil
}

func (p *Proxy) replyFromProxy(req *dns.Msg, remoteAddr *net.UDPAddr) *dns.Msg {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 1500 * time.Millisecond

	queryDomain := req.Question[0].Name
	logrus.Debugln("querying", "query domain", queryDomain)
	// metrics
	// Redis
	//redisConn := p.Api.GetRedis()
	//defer redisConn.Close()
	//setMetrics(redisConn, "total", "qps")
	p.IncrSyncMap(p.QueryMetrics, "qps")

	// cache
	resp := p.replyFromCache(req, queryDomain)
	if resp != nil {
		return resp
	}

	// 查询域名指定dns proxy
	resp = p.queryUpstreamDNS(req, queryDomain)
	if resp != nil {
		return resp
	}

	// upstream
	//setMetrics(redisConn, "total", "recursion")
	//setMetrics(redisConn, "recursion", queryDomain)
	for _, upstream := range p.DefaultDNS {
		if !strings.HasSuffix(upstream, ":53") {
			upstream = upstream + ":53"
		}
		resp, _, err := c.Exchange(req, upstream)
		if err != nil {
			p.IncrSyncMap(p.QueryMetrics, "upstream_timeout")
			logrus.Errorln("exchange: ", err.Error())
			continue
		}
		p.IncrSyncMap(p.QueryMetrics, "recursion")
		p.IncrSyncMap(p.DomainQueryMetrics, queryDomain)
		return resp
	}
	p.IncrSyncMap(p.DomainQueryMetrics, queryDomain)
	p.IncrSyncMap(p.IpQueryMetrics, remoteAddr.IP.String())
	return nil
}

func (p *Proxy) CacheAgentData(c chan error) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in fetchAgentData: %v", r)
			c <- errors.New(fmt.Sprintf("%v", r))
		}
	}()

	for {
		cacheData := p.Api.FetchAgentData(context.Background())
		if cacheData == nil {
			time.Sleep(5 * time.Second)
			logrus.Errorln("Error fetching agent data")
			continue
		}

		dataMap := cacheData["data"].(map[string]interface{})
		for d := range dataMap {
			// 判断是不是map
			if _, ok := dataMap[d].(map[string]interface{}); ok && d == "upstream_proxy" {
				// 清空p.CacheDomain
				p.Lock.Lock()
				_dataMap, ok := dataMap[d].(map[string]interface{})
				if !ok {
					logrus.Errorln("dataMap[d] is not map[string]interface{}")
					p.Lock.Unlock()
					continue
				}
				p.CacheDomain = make(map[string]interface{}, len(_dataMap))
				for k := range _dataMap {
					val := _dataMap[k]
					err := p.Cache.Set(k, val)
					if err != nil {
						logrus.Errorln("GCache.Set() returned error", err)
					}
					p.CacheDomain[k] = val
				}
				p.Lock.Unlock()
			} else if _, ok := dataMap[d].(map[string]interface{}); ok {
				// upstream_dns
				_dataMap := dataMap[d].(map[string]interface{})
				for k := range _dataMap {
					val := _dataMap[k]
					err := p.Cache.Set(k, val)
					if err != nil {
						logrus.Errorln("GCache.Set() returned error", err)
					}
				}
			} else {
				val := dataMap[d]
				err := p.Cache.Set(d, val)
				if err != nil {
					logrus.Errorln("GCache.Set() returned error", err)
				}
			}
		}
		time.Sleep(15 * time.Second)
	}
}

func (p *Proxy) FetchAgentData(c chan error) {
	// TODO, 待删除
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in fetchAgentData: %v", r)
			c <- errors.New(fmt.Sprintf("%v", r))
		}
	}()
	redisConn := p.Api.GetRedis()
	defer redisConn.Close()
	var data map[string]interface{}
	var serverVersion string
	for {
		localVersion := redisConn.Get(redisConn.Context(), "fetch_agent_data_version").Val()
		if data == nil {
			_d := p.Api.FetchAgentData(context.Background())
			data = _d["data"].(map[string]interface{})
			serverVersion = data["version"].(string)
		} else {
			_d := p.Api.FetchAgentData(context.WithValue(context.Background(), "action", "version"))
			innerData := _d["data"].(map[string]interface{})
			serverVersion = innerData["version"].(string)
		}

		if localVersion != serverVersion {
			// 更新数据
			_d := p.Api.FetchAgentData(context.Background())
			data = _d["data"].(map[string]interface{})

			if upstreamDNS, ok := data["upstream_dns"]; ok {
				redisConn.Set(redisConn.Context(), "upstream_dns", upstreamDNS, 30*time.Second)
			}

			if upstreamProxy, ok := data["upstream_proxy"]; ok {
				jsonData, _ := json.Marshal(upstreamProxy)
				redisConn.Set(redisConn.Context(), "upstream_proxy", jsonData, 30*time.Second)
			}

			domainRecords := data["domain_record"].(map[string]interface{})
			for domain, record := range domainRecords {
				redisConn.HSet(redisConn.Context(), domain, record.(map[string]interface{}))
				redisConn.Expire(redisConn.Context(), domain, 30*time.Second)
			}
			redisConn.Set(redisConn.Context(), "fetch_agent_data_version", serverVersion, 30*time.Second)
		} else {
			upstreamDNS := redisConn.Get(redisConn.Context(), "upstream_dns").Val()
			if upstreamDNS == "" {
				redisConn.Set(redisConn.Context(), "upstream_dns", data["upstream_dns"], 30*time.Second)
			} else {
				redisConn.Expire(redisConn.Context(), "upstream_dns", 30*time.Second)
			}

			upstreamProxy := redisConn.Get(redisConn.Context(), "upstream_proxy").Val()
			if upstreamProxy == "" {
				jsonData, _ := json.Marshal(data["upstream_proxy"])
				redisConn.Set(redisConn.Context(), "upstream_proxy", jsonData, 30*time.Second)
			} else {
				redisConn.Expire(redisConn.Context(), "upstream_proxy", 30*time.Second)
			}

			redisConn.Expire(redisConn.Context(), "fetch_agent_data_version", 30*time.Second)
			domainRecords := data["domain_record"].(map[string]interface{})
			for domain, _ := range domainRecords {
				redisConn.Expire(redisConn.Context(), domain, 30*time.Second)
			}
		}
		time.Sleep(15 * time.Second)
	}
}

func syncMapToMap(syncMap *sync.Map) map[string]interface{} {
	result := make(map[string]interface{})
	syncMap.Range(func(key, value interface{}) bool {
		result[key.(string)] = value
		return true
	})
	return result
}

func (p *Proxy) pushAgentMetrics(channel chan error) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in fetchAgentData: %v", r)
			channel <- errors.New(fmt.Sprintf("%v", r))
		}
	}()
	var metrics map[string]interface{}
	for {
		time.Sleep(30 * time.Second)
		// 清空metrics
		metrics = make(map[string]interface{})

		metrics["query_metrics"] = syncMapToMap(p.QueryMetrics)
		metrics["domain_query_metrics"] = syncMapToMap(p.DomainQueryMetrics)
		metrics["ip_query_metrics"] = syncMapToMap(p.IpQueryMetrics)
		metrics["hijack_query_metrics"] = syncMapToMap(p.HijackQueryMetrics)
		metrics["match_recursion_query_metrics"] = syncMapToMap(p.MatchRecursionQueryMetrics)

		if metrics != nil && len(metrics) > 0 {
			p.Api.PushMetrics(metrics)
		}

		p.ClearSyncMap()
	}
}

func (p *Proxy) pushAgentMetrics1(channel chan error) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in fetchAgentData: %v", r)
			channel <- errors.New(fmt.Sprintf("%v", r))
		}
	}()
	var metrics map[string]interface{}
	for {
		time.Sleep(30 * time.Second)
		redisConn := p.Api.GetRedis()
		// 清空metrics
		metrics = make(map[string]interface{})

		for _, field := range []string{"query_metrics", "domain_query_metrics", "ip_query_metrics",
			"hijack_query_metrics", "match_recursion_query_metrics"} {
			data := redisConn.HGetAll(redisConn.Context(), field).Val()
			if data != nil && len(data) > 0 {
				metrics[field] = data
			}
		}

		if metrics != nil && len(metrics) > 0 {
			p.Api.PushMetrics(metrics)
		}

		resetMetrics(redisConn)
		redisConn.Close()
	}
}

func resetMetrics(c *redis.Client) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in resetMetrics: %v", r)
		}
	}()

	c.Del(c.Context(), "query_metrics")
	c.Del(c.Context(), "domain_query_metrics")
	c.Del(c.Context(), "ip_query_metrics")
	c.Del(c.Context(), "hijack_query_metrics")
	c.Del(c.Context(), "match_recursion_query_metrics")
}

func setMetrics(c *redis.Client, key string, value string) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic in setMetrics: %v", r)
		}
	}()

	var redisKey string
	if key == "ip" {
		redisKey = "ip_query_metrics"
	} else if key == "domain" {
		redisKey = "domain_query_metrics"
	} else if key == "hijack" {
		redisKey = "hijack_query_metrics"
	} else if key == "match_recursion" {
		redisKey = "match_recursion_query_metrics"
	} else {
		redisKey = "query_metrics"
	}
	result, err := c.HIncrBy(c.Context(), redisKey, value, 1).Result()
	if err != nil {
		return
	}
	logrus.Println("Set metrics:", result)
}

func (p *Proxy) queryUpstreamDNS(req *dns.Msg, domain string) *dns.Msg {
	// 检查有无完全匹配的域名
	upstreamDNSProxy, _ := p.Cache.Get(domain)

	// 最糟糕的情况，没有匹配的域名
	// 遍历cache中的域名，找到最长匹配的域名
	if upstreamDNSProxy == nil {
		p.Lock.RLock()
		length := 0
		for k := range p.CacheDomain {
			if strings.HasSuffix(domain, k) && len(k) > length {
				length = len(k)
				upstreamDNSProxy = p.CacheDomain[k]
			}
		}
		p.Lock.RUnlock()
	}

	if upstreamDNSProxy == nil {
		upstreamDNS, err := p.Cache.Get("upstream_dns")
		if err != nil {
			logrus.Errorln("Error getting upstream_dns from cache:", err)
			return nil
		} else {
			upstreamDNSProxy = upstreamDNS
		}
	}

	var upstreamDNSList []string

	switch upstreamDNSProxy.(type) {
	case string:
		upstreamDNSList = strings.Split(upstreamDNSProxy.(string), ",")
	case []string:
		upstreamDNSList = upstreamDNSProxy.([]string)
	default:
		// TODO,待验证返回nil还是返回空消息
		emptyMsg := &dns.Msg{}
		emptyMsg.SetReply(req)
		emptyMsg.Authoritative = true
		return emptyMsg
	}

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 1500 * time.Millisecond
	queryMsg := &dns.Msg{}
	queryMsg.SetQuestion(domain, dns.TypeA)
	if len(upstreamDNSList) != 0 {
		p.IncrSyncMap(p.QueryMetrics, "match_recursion")
		p.IncrSyncMap(p.MatchRecursionQueryMetrics, domain)
	}
	for idx, upstream := range upstreamDNSList {
		if !strings.HasSuffix(upstream, ":53") {
			upstream = upstream + ":53"
		}
		resp, _, err := c.Exchange(queryMsg, upstream)
		if err != nil {
			logrus.Errorln("upstream exchange: ", idx, err.Error())
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			// TODO, 是否需要增加cache？？？？
			queryResp := &dns.Msg{}
			queryResp.SetReply(req)
			queryResp.Authoritative = true
			if resp.Answer != nil {
				queryResp.Answer = append(queryResp.Answer, resp.Answer...)
				//			var address string
				//			switch rr := resp.Answer[0].(type) {
				//			case *dns.A:
				//				address = rr.A.String()
				//			case *dns.AAAA:
				//				address = rr.AAAA.String()
				//			}
				//			err = p.Cache.Set(domain, map[string]interface{}{
				//				"type":  "A",
				//				"value": address,
				//			})
				//			if err != nil {
				//				return nil
				//			}
				//		}
				return queryResp
			}
		}
	}
	return nil
}

func (p *Proxy) queryUpstreamDNSr(r *redis.Client, req *dns.Msg, domain string) *dns.Msg {
	// 检查有无完全匹配的域名
	upstreamDNSProxy, _ := p.Cache.Get(domain)

	// 最糟糕的情况，没有匹配的域名
	// 遍历cache中的域名，找到最长匹配的域名
	if upstreamDNSProxy == nil {
		p.Lock.RLock()
		length := 0
		for k := range p.CacheDomain {
			if strings.HasSuffix(domain, k) && len(k) > length {
				length = len(k)
				upstreamDNSProxy = p.CacheDomain[k]
			}
		}
		p.Lock.RUnlock()
	}

	if upstreamDNSProxy == nil {
		upstreamDNS, err := p.Cache.Get("upstream_dns")
		if err != nil {
			logrus.Errorln("Error getting upstream_dns from cache:", err)
			return nil
		} else {
			upstreamDNSProxy = upstreamDNS
		}
	}

	var upstreamDNSList []string

	switch upstreamDNSProxy.(type) {
	case string:
		upstreamDNSList = strings.Split(upstreamDNSProxy.(string), ",")
	case []string:
		upstreamDNSList = upstreamDNSProxy.([]string)
	default:
		// TODO,待验证返回nil还是返回空消息
		emptyMsg := &dns.Msg{}
		emptyMsg.SetReply(req)
		emptyMsg.Authoritative = true
		return emptyMsg
	}

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 1500 * time.Millisecond
	queryMsg := &dns.Msg{}
	queryMsg.SetQuestion(domain, dns.TypeA)
	if len(upstreamDNSList) != 0 {
		setMetrics(r, "total", "match_recursion")
		setMetrics(r, "match_recursion", domain)
	}
	for idx, upstream := range upstreamDNSList {
		if !strings.HasSuffix(upstream, ":53") {
			upstream = upstream + ":53"
		}
		resp, _, err := c.Exchange(queryMsg, upstream)
		if err != nil {
			logrus.Errorln("upstream exchange: ", idx, err.Error())
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			// TODO, 是否需要增加cache？？？？
			queryResp := &dns.Msg{}
			queryResp.SetReply(req)
			queryResp.Authoritative = true
			if resp.Answer != nil {
				queryResp.Answer = append(queryResp.Answer, resp.Answer...)
				//			var address string
				//			switch rr := resp.Answer[0].(type) {
				//			case *dns.A:
				//				address = rr.A.String()
				//			case *dns.AAAA:
				//				address = rr.AAAA.String()
				//			}
				//			err = p.Cache.Set(domain, map[string]interface{}{
				//				"type":  "A",
				//				"value": address,
				//			})
				//			if err != nil {
				//				return nil
				//			}
				//		}
				return queryResp
			}
		}
	}
	return nil
}

func main() {
	var cacheSize int
	var filename string
	var defaultdns string
	var logLevel string
	flag.IntVar(&cacheSize, "cache-size", 100000, "cache size")
	flag.StringVar(&filename, "config", "config.yaml", "config file")
	flag.StringVar(&defaultdns, "default-dns", "8.8.8.8:53", "default dns")
	flag.StringVar(&logLevel, "log-level", "warn", "log level")
	flag.Parse()

	defaultDns := strings.Split(defaultdns, ",")

	if logLevel == "debug" {
		logrus.SetLevel(logrus.DebugLevel)
	} else if logLevel == "info" {
		logrus.SetLevel(logrus.InfoLevel)
	} else if logLevel == "warn" {
		logrus.SetLevel(logrus.WarnLevel)
	} else if logLevel == "error" {
		logrus.SetLevel(logrus.ErrorLevel)
	} else if logLevel == "fatal" {
		logrus.SetLevel(logrus.FatalLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	proxy := &Proxy{
		Cache:                      gcache.New(cacheSize).Expiration(30 * time.Second).ARC().Build(),
		Listener:                   nil,
		Api:                        NewDNSGuardAPI(filename),
		DefaultDNS:                 defaultDns,
		Lock:                       &sync.RWMutex{},
		MetricLock:                 &sync.RWMutex{},
		QueryMetrics:               &sync.Map{},
		DomainQueryMetrics:         &sync.Map{},
		IpQueryMetrics:             &sync.Map{},
		HijackQueryMetrics:         &sync.Map{},
		MatchRecursionQueryMetrics: &sync.Map{},
	}

	backlogSize := 4096
	listenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			if err = c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, backlogSize)
			}); err != nil {
				return err
			}
			return nil
		},
	}
	listener, err := listenConfig.ListenPacket(context.Background(), "udp", ":53")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	// 设置listener backlog
	proxy.Listener = listener.(*net.UDPConn)
	defer proxy.Listener.Close()

	restartChan := make(chan error)
	go func() {
		for {
			err := <-restartChan
			if err != nil {
				logrus.Errorln("Server exited with error:", err)
			}
			logrus.Println("Restarting server...")
			time.Sleep(2 * time.Second) // Wait before restarting
			go proxy.ServeDNS(restartChan)
		}
	}()

	go proxy.ServeDNS(restartChan)

	fetchChan := make(chan error)
	go func() {
		for {
			err := <-fetchChan
			if err != nil {
				logrus.Errorln("Fetch agent data exited with error:", err)
			}
			logrus.Println("Restarting fetch agent data...")
			time.Sleep(2 * time.Second) // Wait before restarting
			go proxy.CacheAgentData(fetchChan)
		}
	}()
	go proxy.CacheAgentData(fetchChan)

	pushMetricsChan := make(chan error)
	go func() {
		for {
			err := <-pushMetricsChan
			if err != nil {
				logrus.Errorln("Push agent metrics exited with error:", err)
			}
			logrus.Println("Restarting push agent metrics...")
			time.Sleep(2 * time.Second) // Wait before restarting
			go proxy.pushAgentMetrics(pushMetricsChan)
		}
	}()

	go proxy.pushAgentMetrics(pushMetricsChan)

	r := gin.Default()
	r.GET("/metrics", func(c *gin.Context) {
		class := c.Query("class")
		if class == "" {
			metrics := map[string]interface{}{}
			metrics["query_metrics"] = syncMapToMap(proxy.QueryMetrics)
			metrics["domain_query_metrics"] = syncMapToMap(proxy.DomainQueryMetrics)
			metrics["ip_query_metrics"] = syncMapToMap(proxy.IpQueryMetrics)
			metrics["hijack_query_metrics"] = syncMapToMap(proxy.HijackQueryMetrics)
			metrics["match_recursion_query_metrics"] = syncMapToMap(proxy.MatchRecursionQueryMetrics)
			c.JSON(http.StatusOK, metrics)
		} else if class == "query_metrics" {
			c.JSON(http.StatusOK, syncMapToMap(proxy.QueryMetrics))
		} else if class == "domain_query_metrics" {
			c.JSON(http.StatusOK, syncMapToMap(proxy.DomainQueryMetrics))
		} else if class == "ip_query_metrics" {
			c.JSON(http.StatusOK, syncMapToMap(proxy.IpQueryMetrics))
		} else if class == "hijack_query_metrics" {
			c.JSON(http.StatusOK, syncMapToMap(proxy.HijackQueryMetrics))
		} else if class == "match_recursion_query_metrics" {
			c.JSON(http.StatusOK, syncMapToMap(proxy.MatchRecursionQueryMetrics))
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "class not found"})
		}
	})

	r.GET("/cache", func(c *gin.Context) {
		domain := c.Query("domain")
		proxy.Lock.RLock()
		defer proxy.Lock.RUnlock()
		if domain != "" {
			if val, ok := proxy.CacheDomain[domain]; ok {
				c.JSON(http.StatusOK, val)
			} else {
				c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			}
		} else {
			c.JSON(http.StatusOK, proxy.CacheDomain)
		}
	})

	r.GET("/gcache", func(c *gin.Context) {
		domain := c.Query("domain")
		val, err := proxy.Cache.Get(domain)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		} else {
			c.JSON(http.StatusOK, val)
		}
	})

	r.GET("/status", func(c *gin.Context) {
		qps, ok := proxy.QueryMetrics.Load("qps")
		if !ok {
			qps = -1
		}
		c.JSON(http.StatusOK, gin.H{
			"status":      "ok",
			"go_routines": runtime.NumGoroutine(),
			"gcache":      len(proxy.Cache.Keys(true)),
			"qps":         qps,
		})
	})

	err = r.Run(":80")
	if err != nil {
		return
	}

}
