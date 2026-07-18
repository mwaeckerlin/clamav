/**

ClamAV init: minimal, shell-free supervision for the clamav container.

Same three-stage / scratch / statically-linked C++ pattern as the
sibling mwaeckerlin/rspamd and mwaeckerlin/redis containers.

Behaviour:

  0. Validate every configuration env value (whitelist per value class)
     before rendering it into clamd.conf/freshclam.conf — a malformed
     value aborts the start with a clear `invalid <VAR>` error instead
     of injecting directives into the generated config files.
  1. Ensure /var/lib/clamav is writable and contains a virus database.
     - If it is empty (fresh install), run `freshclam` synchronously
       once to bootstrap the DB. This can take a few minutes on first
       start; it happens exactly once per volume.
     - If it already has a `main.cvd`/`main.cld`, skip the sync step
       and rely on the background daemon to keep it current.
  2. Fork off `freshclam --daemon --foreground` as a child so it stays
     alive and updates the DB on the interval configured by
     FRESHCLAM_CHECKS (default: 24 checks/day, i.e. hourly). Freshclam
     is best-effort: if the internet is unreachable for a while,
     clamd keeps running with the last downloaded signatures. Failed
     freshclam runs are logged, they do not affect scanning.
  3. execv `clamd --foreground --config-file=/etc/clamav/clamd.conf`.
     clamd becomes PID 1 in the container. When the container stops,
     Docker sends SIGTERM to PID 1 (clamd), which cleanly shuts down;
     the freshclam child is reaped by the kernel via init-adoption.

Supports --healthcheck: TCP-probes port 3310 (clamd's default) on
127.0.0.1 — a successful connect means clamd is accepting requests.

*/

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr const char *CLAMD           = "/usr/sbin/clamd";
constexpr const char *FRESHCLAM       = "/usr/bin/freshclam";
constexpr const char *DB_DIR          = "/var/lib/clamav";
constexpr const char *CLAMD_CONF      = "/etc/clamav/clamd.conf";
constexpr const char *FRESHCLAM_CONF  = "/etc/clamav/freshclam.conf";

std::string
env_or(const char *name, const std::string &fallback = {}) {
  const char *v = std::getenv(name);
  return (v && *v) ? std::string(v) : fallback;
}

void
write_file(const fs::path &p, const std::string &content) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  if (!out) throw std::runtime_error("cannot write " + p.string());
  out << content;
}

// Every env value is rendered verbatim into a key-space-value config
// file, so an unvalidated value — a newline above all — would inject
// arbitrary extra directives into clamd.conf/freshclam.conf. Operator
// input is input: whitelist-validate each value class and refuse to
// start on anything malformed (pinned by tests/config-validation.sh).
[[noreturn]] void
die_invalid(const char *var, const std::string &value) {
  std::cerr << "**** ERROR: invalid " << var << " \"" << value
            << "\" — refusing to start" << std::endl;
  std::exit(1);
}

void
check_chars(const char *var, const std::string &v, const std::string &extra) {
  if (v.empty()) die_invalid(var, v);
  for (char c : v)
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        extra.find(c) == std::string::npos)
      die_invalid(var, v);
}

long
check_num(const char *var, const std::string &v, long min, long max) {
  if (v.empty() || v.size() > 9 ||
      v.find_first_not_of("0123456789") != std::string::npos)
    die_invalid(var, v);
  long n = std::atol(v.c_str());
  if (n < min || n > max) die_invalid(var, v);
  return n;
}

// clamd size values: plain bytes or a single K/M/G suffix.
void
check_size(const char *var, const std::string &v) {
  auto suffix = v.find_first_not_of("0123456789");
  if (v.empty() || suffix == 0) die_invalid(var, v);
  if (suffix == std::string::npos) return;
  if (suffix != v.size() - 1 ||
      std::string("KkMmGg").find(v[suffix]) == std::string::npos)
    die_invalid(var, v);
}

bool
db_exists() {
  if (!fs::exists(DB_DIR)) return false;
  for (const auto &e : fs::directory_iterator(DB_DIR)) {
    auto name = e.path().filename().string();
    if (name == "main.cvd" || name == "main.cld") return true;
  }
  return false;
}

int
run_wait(const std::vector<const char *> &argv) {
  pid_t pid = fork();
  if (pid < 0) throw std::runtime_error("fork");
  if (pid == 0) {
    std::vector<char *> a;
    for (auto *s : argv) a.push_back(const_cast<char *>(s));
    a.push_back(nullptr);
    execvp(a[0], a.data());
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void
spawn_detached(const std::vector<const char *> &argv) {
  pid_t pid = fork();
  if (pid < 0) throw std::runtime_error("fork");
  if (pid == 0) {
    // Child: replace with freshclam. Don't setsid — we WANT the child
    // to be signalled when clamd (PID 1) receives SIGTERM.
    std::vector<char *> a;
    for (auto *s : argv) a.push_back(const_cast<char *>(s));
    a.push_back(nullptr);
    execvp(a[0], a.data());
    _exit(127);
  }
  // Parent returns immediately; the child is our sibling in the process
  // tree until we execv() ourselves into clamd, at which point clamd
  // becomes PID 1 and the freshclam child is orphaned + adopted.
}

int
tcp_probe(int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return 1;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  int rc = connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr);
  close(s);
  return rc == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) try {
  const std::string checks_per_day = env_or("FRESHCLAM_CHECKS", "24");
  const std::string mirror         = env_or("FRESHCLAM_MIRROR", "database.clamav.net");
  // Scan-size limits, set to clamav's architectural maxima so as much
  // of a mail as clamav CAN scan is scanned. These are hard, RAM/design
  // bounds inside clamav — they cannot be raised to arbitrary values:
  //   MaxFileSize     — internally capped at 2 GiB; a single file/embedded
  //                     file larger than that is skipped (not scannable).
  //   MaxScanSize     — total scan budget across a message/archive.
  //   StreamMaxLength — the INSTREAM path rspamd uses; ~4 GiB ceiling.
  //                     clamd's own default is only 25 MB, which would
  //                     abort the stream for any larger mail — so it MUST
  //                     be raised.
  // A mail larger than what clamav can scan (roughly >2 GiB per file /
  // >4 GiB per message) is delivered UNSCANNED, never bounced — Rspamd's
  // antivirus module reports CLAM_VIRUS_FAIL (weight 0, no action). This
  // gap is a clamav limitation, not a configurable-away one: MESSAGE_SIZE_LIMIT
  // (postfix, 100 GiB) is intentionally far higher than anything clamav
  // can scan. Fail-open keeps large legitimate mail flowing.
  const std::string max_size       = env_or("CLAMD_MAX_FILESIZE",    "2G");
  const std::string max_scan       = env_or("CLAMD_MAX_SCANSIZE",    "4G");
  const std::string stream_max     = env_or("CLAMD_STREAM_MAXLENGTH", "4G");
  const std::string bind           = env_or("CLAMD_BIND",            "0.0.0.0");

  // Validate every env value before it is rendered anywhere — also on
  // the --healthcheck path, so a misconfigured container reports
  // unhealthy instead of probing a port that clamd never bound.
  const int tcp_port =
      static_cast<int>(check_num("CLAMD_PORT", env_or("CLAMD_PORT", "3310"), 1, 65535));
  check_num("FRESHCLAM_CHECKS", checks_per_day, 1, 50);  // freshclam's valid range
  check_chars("FRESHCLAM_MIRROR", mirror, ".-:/_");      // hostname or URL
  check_chars("CLAMD_BIND", bind, ".:-");                // IPv4/IPv6/hostname
  check_size("CLAMD_MAX_FILESIZE", max_size);
  check_size("CLAMD_MAX_SCANSIZE", max_scan);
  check_size("CLAMD_STREAM_MAXLENGTH", stream_max);

  if (argc > 1 && std::string(argv[1]) == "--healthcheck")
    return tcp_probe(tcp_port);

  // 1. Compose freshclam.conf and clamd.conf. They are simple
  //    key-space-value files, no templating needed.
  fs::create_directories("/etc/clamav");
  write_file(FRESHCLAM_CONF,
      "DatabaseDirectory " + std::string(DB_DIR) + "\n"
      "DatabaseMirror " + mirror + "\n"
      "Checks " + checks_per_day + "\n"
      "NotifyClamd " + std::string(CLAMD_CONF) + "\n"  // reload clamd right after an update
      "LogVerbose no\n"
      "LogTime yes\n"
      "Foreground yes\n"       // for --daemon --foreground mode below
  );
  write_file(CLAMD_CONF,
      "DatabaseDirectory " + std::string(DB_DIR) + "\n"
      "TCPSocket " + std::to_string(tcp_port) + "\n"
      "TCPAddr " + bind + "\n"
      "MaxFileSize " + max_size + "\n"
      "MaxScanSize " + max_scan + "\n"
      "StreamMaxLength " + stream_max + "\n"
      "LogTime yes\n"
      "LogSyslog no\n"
      "Foreground yes\n"       // required for --foreground below
      "SelfCheck 3600\n"       // reload DB hourly if freshclam updated
      "User clamav\n"
  );

  // 2. Bootstrap the virus DB if the volume is empty. Blocking; can
  //    take ~5 minutes on first-ever start (full ~200 MB download).
  if (!db_exists()) {
    std::cerr << "**** No virus DB in " << DB_DIR
              << " — running initial freshclam sync (may take minutes) …"
              << std::endl;
    int rc = run_wait({FRESHCLAM, "--config-file=/etc/clamav/freshclam.conf", "--stdout"});
    if (rc != 0) {
      std::cerr << "**** WARNING: initial freshclam failed (exit " << rc
                << "). clamd will still try to start; if no DB is present "
                    "yet, it will refuse. Check network and mirror reachability."
                << std::endl;
    }
  }

  // 3. Start freshclam in --daemon --foreground so it stays a child
  //    of our init, polls the mirror on the configured interval and
  //    notifies clamd (RELOAD via NotifyClamd; clamd's own SelfCheck
  //    loop is the fallback) when new signatures land.
  spawn_detached({FRESHCLAM, "--daemon", "--config-file=/etc/clamav/freshclam.conf", "--stdout"});
  std::this_thread::sleep_for(std::chrono::milliseconds(200));  // let freshclam log its greeting first

  // 4. execv into clamd; it becomes PID 1. The freshclam child is
  //    reparented by the kernel; when Docker sends SIGTERM to us
  //    (clamd), clamd shuts down cleanly and Docker reaps the child.
  std::cerr << "**** Starting clamd on " << bind << ":" << tcp_port
            << " with " << checks_per_day << " DB checks/day from "
            << mirror << std::endl;

  const char *exec_argv[] = {"clamd", "--foreground",
                             "--config-file=/etc/clamav/clamd.conf", nullptr};
  execv(CLAMD, const_cast<char *const *>(exec_argv));
  std::perror(CLAMD);
  return 1;
} catch (const std::exception &e) {
  std::cerr << "EXCEPTION: " << e.what() << std::endl;
  return 1;
} catch (...) {
  std::cerr << "UNKNOWN ERROR" << std::endl;
  return 1;
}
