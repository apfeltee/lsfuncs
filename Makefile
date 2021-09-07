
src = main.cpp
exe = lsfuncs.exe

# ----

#cxx = clang++ -std=c++17 -m32
#cxx = clang++ -std=c++17 -O3
cxx = g++ -std=c++17 -g3 -ggdb
cflags = -Wall -Wextra
lflags = -limagehlp -lshlwapi 

all:
	$(cxx) $(cflags) $(src) -o $(exe) $(lflags)

