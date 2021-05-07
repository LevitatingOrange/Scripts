all: build completion

build:
	go build -o bin/scripts .

clean:
	rm bin/*

completion:
	bin/scripts completion zsh > _scripts_completion

copy_domains:
	cp -r ~/.vpn-domains cmd/domains
