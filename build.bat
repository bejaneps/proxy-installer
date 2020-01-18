:: for go modules to work
SET GOPATH=%cd%
SET GO111MODULE=on

:: change this path, if your MSBUILD is located somewhere else
SET MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBUILD.exe

mkdir build

:: building installer
cd frp

go build -o ..\build\installer.exe .\cmd\installer

cd ..

:: creating dirs for ServiceTree
mkdir "C:\Program Files\ServiceTree"
mkdir "C:\Program Files\ServiceTree\rca"
mkdir "C:\Program Files\ServiceTree\rsa"

mkdir "C:\ProgramData\.ServiceTree"

mkdir "C:\ProgramData\ssh"

:: generating ssh keys
ssh-keygen -A

:: building winvnc, setpasswd and etc
mkdir services\build
"%MSBUILD%" services\rc.sln

:: copying all built executables to build directory
cd services\Debug

copy winvnc.exe "C:\Program Files\ServiceTree\"
copy winvnc.ini "C:\Program Files\ServiceTree\"
copy setpasswd.exe "C:\Program Files\ServiceTree\"

cd ..\..\