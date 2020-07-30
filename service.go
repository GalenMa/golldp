package main

import (
	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
)

type Service struct{}

func (p *Service) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *Service) run() {
	getAllInterfacesLLDPInfo()
}

func (p *Service) Stop(s service.Service) error {
	return nil
}


func StartService() {
	svcConfig := &service.Config{
		Name: "golldp",
		DisplayName: "golldp",
		Description: "get lldp info by golldp",
	}
	prg := &Service{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatalf("start service error. err:%v", err)
	}

	if err = s.Run(); err != nil {
		log.Fatalf("run service error. err:%v", err)
	}
}