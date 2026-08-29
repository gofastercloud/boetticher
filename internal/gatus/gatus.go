package gatus

import (
	"fmt"
	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
	"sort"
)

type endpoint struct {
	Name       string   `yaml:"name"`
	Group      string   `yaml:"group"`
	URL        string   `yaml:"url"`
	Interval   string   `yaml:"interval"`
	Conditions []string `yaml:"conditions"`
}
type configuration struct {
	Web struct {
		Port int `yaml:"port"`
	} `yaml:"web"`
	Storage struct {
		Type string `yaml:"type"`
	} `yaml:"storage"`
	Endpoints []endpoint `yaml:"endpoints"`
}

func RenderConfiguration(site model.Site) ([]byte, error) {
	if err := site.Validate(); err != nil {
		return nil, err
	}
	items := []endpoint{}
	for _, d := range site.Declarations {
		if d.Module == "gatus" {
			continue
		}
		for _, g := range d.Guests {
			if g.URL != "" && g.ProductOwned && g.Module != "" {
				items = append(items, endpoint{g.Name, d.Module, g.URL, "1m", []string{"[STATUS] == 200"}})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Group != items[j].Group {
			return items[i].Group < items[j].Group
		}
		return items[i].Name < items[j].Name
	})
	c := configuration{}
	c.Web.Port = 8080
	c.Storage.Type = "memory"
	c.Endpoints = items
	b, e := yaml.Marshal(c)
	if e != nil {
		return nil, fmt.Errorf("encode Gatus configuration: %w", e)
	}
	return b, nil
}
