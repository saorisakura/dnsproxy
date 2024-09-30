package main

import (
	"context"
	"github.com/bluele/gcache"
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
