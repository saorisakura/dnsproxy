# 在macOS环境下编译
mac:
	go build -o ./bin/$(shell basename `pwd`).mac .

# 交叉编译Linux环境下的64位可执行程序
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/$(shell basename `pwd`).linux .
