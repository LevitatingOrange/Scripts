all: build completion

build:
	go build -o bin/scripts .

clean:
	rm bin/*

completion:
	bin/scripts completion zsh > _scripts

copy_domains:
	cp -Lr ~/.vpn-domains cmd/domains
