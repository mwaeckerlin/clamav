/**

ClamAV init: minimal, shell-free supervision for the clamav container.

Same three-stage / scratch / statically-linked C++ pattern as the
sibling mwaeckerlin/rspamd and mwaeckerlin/redis containers.

Behaviour:

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
  const int tcp_port = std::atoi(env_or("CLAMD_PORT", "3310").c_str());

  if (argc > 1 && std::string(argv[1]) == "--healthcheck")
    return tcp_probe(tcp_port);

  const std::string checks_per_day = env_or("FRESHCLAM_CHECKS", "24");
  const std::string mirror         = env_or("FRESHCLAM_MIRROR", "database.clamav.net");
  // Scan-size limits. Kept very high on purpose: a message larger than
  // these is not fully scanned (see below), so a low limit would silently
  // leave normal large attachments unscanned. Defaults are 1 GiB — high
  // enough to cover any realistic mail while still bounding a
  // resource-exhaustion attack. All configurable via env.
  const std::string max_size       = env_or("CLAMD_MAX_FILESIZE",    "1G");
  const std::string max_scan       = env_or("CLAMD_MAX_SCANSIZE",    "1G");
  // StreamMaxLength bounds the INSTREAM path that rspamd uses. clamd's
  // own default (25 MB) would abort the stream for any larger mail, so
  // it MUST be raised to match/exceed the scan sizes — otherwise big
  // mails arrive at clamd only to be refused mid-stream. Fail behaviour
  // stays fail-open: a mail exceeding even this is delivered unscanned
  // (rspamd's antivirus module only reports CLAM_VIRUS_FAIL, weight 0,
  // no reject), never bounced.
  const std::string stream_max     = env_or("CLAMD_STREAM_MAXLENGTH", "1G");
  const std::string bind           = env_or("CLAMD_BIND",            "0.0.0.0");

  // 1. Compose freshclam.conf and clamd.conf. They are simple
  //    key-space-value files, no templating needed.
  fs::create_directories("/etc/clamav");
  write_file(FRESHCLAM_CONF,
      "DatabaseDirectory " + std::string(DB_DIR) + "\n"
      "DatabaseMirror " + mirror + "\n"
      "Checks " + checks_per_day + "\n"
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
  //    notifies clamd (via SIGHUP or via clamd's own SelfCheck loop)
  //    when new signatures land.
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
