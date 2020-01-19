:: change this path, if your MSBUILD is located somewhere else
SET MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBUILD.exe
"%MSBUILD%" services\rc.sln -t:clean

:: resetting env variables
SET GOPATH=""
SET GO111MODULE=""

:: deleting all created services
sc stop ServiceTree-winvnc
sc delete ServiceTree-winvnc

sc stop ServiceTree-ssh
sc delete ServiceTree-ssh

NSSM\amd64\nssm.exe stop ServiceTree-rca
NSSM\amd64\nssm.exe remove ServiceTree-rca confirm

rmdir /S "C:\Program Files\ServiceTree"
rmdir /S build
rmdir /S services\Debug*