:: setting env variables is necessary
SET GOPATH=%cd%
SET GO111MODULE=on

:: change this path, if your MSBUILD is located somewhere else
SET MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBUILD.exe

:: building rca and rsa
cd frp

go build -o build\rca.exe .\cmd\frpc
go build -o build\rsa.exe .\cmd\frps

cd ..

:: building winvnc, setpasswd and etc
mkdir services\build
"%MSBUILD%" services\rc.sln -maxcpucount:4