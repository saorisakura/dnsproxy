package main

import (
	"context"
	"github.com/bluele/gcache"
	"github.com/sirupsen/logrus"
	"sync"
	"testing"
	"time"
)

func TestNewDNSGuardAPI(t *testing.T) {
	api := NewDNSGuardAPI("config.yaml")
	if api == nil {
		t.Error("NewDNSGuardAPI() returned nil")
	}
	data := api.FetchAgentData(context.WithValue(context.Background(), "action", "version"))
	if data == nil {
		t.Error("FetchAgentData() returned nil")
	}
	t.Log(data)

	data = api.FetchAgentData(context.Background())
	if data == nil {
		t.Error("FetchAgentData() returned nil")
	}

	t.Run("TestGCacheStore", func(t *testing.T) {
		cache := gcache.New(100000).Expiration(30 * time.Second).ARC().Build()
		dataMap := data["data"].(map[string]interface{})
		for d := range dataMap {
			// 判断是不是map
			if _, ok := dataMap[d].(map[string]interface{}); ok {
				_dataMap := dataMap[d].(map[string]interface{})
				t.Log(d, len(_dataMap))
				for k := range _dataMap {
					val := _dataMap[k]
					err := cache.Set(k, val)
					if err != nil {
						t.Error("GCache.Set() returned error", err)
					}
				}
			} else {
				val := dataMap[d]
				t.Log(d, val)
				err := cache.Set(d, val)
				if err != nil {
					t.Error("GCache.Set() returned error", err)
				}
			}
		}

		t.Run("TestGCacheGet", func(t *testing.T) {
			for d := range dataMap {
				if _, ok := dataMap[d].(map[string]interface{}); ok {
					for k := range dataMap[d].(map[string]interface{}) {
						_, err := cache.Get(k)
						if err != nil {
							t.Error("GCache.Get() returned error", err)
						}
					}
				} else {
					_, err := cache.Get(d)
					if err != nil {
						t.Error("GCache.Get() returned error", err)
					}
				}
			}
		})
	})
}

func TestCacheAgentData(t *testing.T) {
	p := &Proxy{
		Cache:                      gcache.New(100000).Expiration(30 * time.Second).ARC().Build(),
		Listener:                   nil,
		Api:                        NewDNSGuardAPI("config.yaml"),
		DefaultDNS:                 []string{"8.8.8.8"},
		Lock:                       &sync.RWMutex{},
		MetricLock:                 &sync.RWMutex{},
		QueryMetrics:               &sync.Map{},
		DomainQueryMetrics:         &sync.Map{},
		IpQueryMetrics:             &sync.Map{},
		HijackQueryMetrics:         &sync.Map{},
		MatchRecursionQueryMetrics: &sync.Map{},
	}

	cacheData := p.Api.FetchAgentData(context.Background())
	if cacheData == nil {
		t.Error("FetchAgentData() returned nil")
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
				if k == "argocd.funplus-inc.com." {
					t.Log(k, _dataMap[k])
				}
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
	t.Log(len(p.Cache.Keys(true)))
	t.Log(p.Cache.Get("upstream_dns"))
	t.Log(p.Cache.Get("argocd.funplus-inc.com."))
}
