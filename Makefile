all: build completion

build:
	go build -o bin/scripts .

clean:
	rm bin/*

completion:
	bin/scripts completion zsh > _scripts

copy_domains:
	rm -r cmd/domains/
	cp -Lr ~/.vpn-domains/ cmd/domains/
