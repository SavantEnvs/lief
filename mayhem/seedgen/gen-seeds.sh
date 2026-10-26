set -ex
cd /tmp/seedgen
cat > t.c <<'C'
static int tbl[4] = {1,2,3,4};
int g = 7;
int add(int a, int b) { return a + b + tbl[a & 3]; }
int main(void) { return add(g, 2) & 1; }
C
cat > t_pe.c <<'C'
int g = 7;
int add(int a, int b) { return a + b; }
int mainCRTStartup(void) { return add(g, 2); }
C
mkdir -p elf macho pe pkcs7
clang -O1 -g -gdwarf-3 -fPIE -c t.c -o elf/t_x86_64.o
clang -O1 -nostdlib -static -fno-pic -Wl,-e,main t.c -o elf/t_static_x86_64
clang -O1 -shared -fPIC t.c -o elf/t_shared_x86_64.so
clang -O1 --target=aarch64-linux-gnu -c t.c -o elf/t_aarch64.o
clang -O1 --target=arm-linux-gnueabihf -c t.c -o elf/t_arm.o
clang -O1 --target=i386-linux-gnu -c t.c -o elf/t_i386.o
clang -O1 --target=x86_64-apple-macos11 -c t.c -o macho/t_x86_64.o
clang -O1 --target=arm64-apple-macos11 -c t.c -o macho/t_arm64.o
ld64.lld-19 -arch x86_64 -platform_version macos 11.0 11.0 -e _main -o macho/t_exe_x86_64 macho/t_x86_64.o -undefined dynamic_lookup -no_uuid 2>&1 || true
ld64.lld-19 -arch arm64 -platform_version macos 11.0 11.0 -e _main -o macho/t_exe_arm64 macho/t_arm64.o -undefined dynamic_lookup 2>&1 || true
ld64.lld-19 -arch x86_64 -dylib -platform_version macos 11.0 11.0 -o macho/t_x86_64.dylib macho/t_x86_64.o -undefined dynamic_lookup 2>&1 || true
clang -O1 --target=x86_64-windows-msvc -fuse-ld=lld -c t_pe.c -o pe/t_x64.obj
clang -O1 --target=i686-windows-msvc -c t_pe.c -o pe/t_x86.obj
lld-link /machine:x64 /subsystem:console /entry:mainCRTStartup /nodefaultlib /out:pe/t_x64.exe pe/t_x64.obj
lld-link /machine:x86 /subsystem:console /entry:mainCRTStartup /nodefaultlib /out:pe/t_x86.exe pe/t_x86.obj /safeseh:no
lld-link /machine:x64 /dll /noentry /nodefaultlib /out:pe/t_x64.dll pe/t_x64.obj /export:add
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 3650 -subj "/CN=mayhem seed" 2>/dev/null
echo "hello lief" > payload.txt



ls -la elf macho pe pkcs7
python3 /tmp/seedgen/mkauth.py pkcs7/authenticode_sha256.der   # needs c.pem from the openssl req above
