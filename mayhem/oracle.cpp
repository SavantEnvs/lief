// Known-answer probe over LIEF's parsers: parses committed binaries and prints a canonical,
// deterministic dump that mayhem/test.sh diffs against mayhem/oracle.expected.
#include <LIEF/LIEF.hpp>
#include <LIEF/PE/signature/SignatureParser.hpp>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

static void dump_abstract(const std::string& tag, const std::string& path) {
  std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse(path);
  if (!bin) {
    std::printf("%s: PARSE-FAILED\n", tag.c_str());
    return;
  }
  const LIEF::Header hdr = bin->header();
  std::printf("%s: format=%d arch=%d bits64=%d entry=0x%llx pie=%d\n", tag.c_str(),
              (int)bin->format(), (int)hdr.architecture(), (int)hdr.is_64(),
              (unsigned long long)bin->entrypoint(), (int)bin->is_pie());
  for (const LIEF::Section& s : bin->sections()) {
    std::printf("%s: section %s va=0x%llx size=0x%llx\n", tag.c_str(), std::string(s.name()).c_str(),
                (unsigned long long)s.virtual_address(), (unsigned long long)s.size());
  }
  size_t nsym = 0;
  for (const LIEF::Symbol& sym : bin->symbols()) {
    if (sym.name() == "main" || sym.name() == "_main" || sym.name() == "add" ||
        sym.name() == "_add" || sym.name() == "g" || sym.name() == "_g") {
      std::printf("%s: symbol %s value=0x%llx\n", tag.c_str(), std::string(sym.name()).c_str(),
                  (unsigned long long)sym.value());
    }
    ++nsym;
  }
  std::printf("%s: symbols=%zu\n", tag.c_str(), nsym);
}

static void dump_elf(const std::string& path) {
  std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(path);
  if (!elf) {
    std::printf("elf: PARSE-FAILED\n");
    return;
  }
  std::printf("elf: type=%d machine=%d entry=0x%llx sections=%zu segments=%zu\n",
              (int)elf->header().file_type(), (int)elf->header().machine_type(),
              (unsigned long long)elf->header().entrypoint(), elf->sections().size(),
              elf->segments().size());
  for (const LIEF::ELF::Segment& seg : elf->segments()) {
    std::printf("elf: segment type=%d flags=%u filesz=0x%llx memsz=0x%llx va=0x%llx\n",
                (int)seg.type(), (unsigned)seg.flags(), (unsigned long long)seg.physical_size(),
                (unsigned long long)seg.virtual_size(), (unsigned long long)seg.virtual_address());
  }
  for (const LIEF::ELF::Symbol& s : elf->dynamic_symbols()) {
    std::printf("elf: dynsym %s value=0x%llx size=%llu\n", std::string(s.name()).c_str(),
                (unsigned long long)s.value(), (unsigned long long)s.size());
  }
  std::printf("elf: dynamic_entries=%zu\n", elf->dynamic_entries().size());

  // Round-trip: rewrite the binary and reparse it.
  const char* tmpdir = std::getenv("TMPDIR");
  std::string out = std::string(tmpdir ? tmpdir : "/tmp") + "/lief-oracle-roundtrip.elf";
  elf->write(out);
  std::unique_ptr<LIEF::ELF::Binary> again = LIEF::ELF::Parser::parse(out);
  std::remove(out.c_str());
  if (!again) {
    std::printf("elf: ROUNDTRIP-FAILED\n");
    return;
  }
  std::printf("elf: roundtrip entry=0x%llx sections=%zu segments=%zu dynsyms=%zu\n",
              (unsigned long long)again->header().entrypoint(), again->sections().size(),
              again->segments().size(), again->dynamic_symbols().size());
}

static void dump_signature(const std::string& path) {
  LIEF::result<LIEF::PE::Signature> sig = LIEF::PE::SignatureParser::parse(path);
  if (!sig) {
    std::printf("pkcs7 %s: PARSE-FAILED\n", path.substr(path.rfind('/') + 1).c_str());
    return;
  }
  std::printf("pkcs7 %s: version=%u digest=%d certs=%zu signers=%zu\n",
              path.substr(path.rfind('/') + 1).c_str(), (unsigned)sig->version(),
              (int)sig->digest_algorithm(), sig->certificates().size(), sig->signers().size());
  for (const LIEF::PE::x509& crt : sig->certificates()) {
    std::printf("pkcs7 cert subject=%s\n", crt.subject().c_str());
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <repo root>\n", argv[0]);
    return 2;
  }
  LIEF::logging::disable();
  const std::string root = argv[1];
  dump_elf(root + "/tests/elf/hello_lief.bin");
  dump_abstract("elf-x86_64", root + "/tests/elf/hello_lief.bin");
  dump_abstract("elf-aarch64", root + "/tests/elf/hello_lief_aarch64.bin");
  dump_abstract("elf-obj", root + "/mayhem/elf_fuzzer/testsuite/t_x86_64.o");
  dump_abstract("elf-so", root + "/mayhem/elf_fuzzer/testsuite/t_shared_x86_64.so");
  dump_abstract("macho-exe", root + "/mayhem/macho_fuzzer/testsuite/t_exe_x86_64");
  dump_abstract("macho-arm64", root + "/mayhem/macho_fuzzer/testsuite/t_exe_arm64");
  dump_abstract("macho-dylib", root + "/mayhem/macho_fuzzer/testsuite/t_x86_64.dylib");
  dump_abstract("pe-exe", root + "/mayhem/pe_fuzzer/testsuite/t_x64.exe");
  dump_abstract("pe-x86", root + "/mayhem/pe_fuzzer/testsuite/t_x86.exe");
  dump_abstract("pe-dll", root + "/mayhem/pe_fuzzer/testsuite/t_x64.dll");
  dump_signature(root + "/mayhem/pkcs7_signature/testsuite/authenticode_sha256.der");
  return 0;
}
