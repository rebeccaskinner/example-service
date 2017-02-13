param "logfile" {
  default = "/var/log/example-service.log"
}

param "state" {
  default = "running"
}

file.content "example.service" {
  destination = "/lib/systemd/system/example.service"
  content = <<EOF
[Unit]
Description=A well behaved daemon that does nothing
Requires=example.socket
After=network.target auditd.service

[Service]
ExecStart=/usr/sbin/example-service --log-to {{param `logfile`}} --foreground
ExecReload=/usr/bin/example-service --reload
PIDFile=/var/run/example-service.pid
KillSignal=SIGINT
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify

[Install]
WantedBy=multi-user.target
EOF
}

file.content "example.socket" {
  destination = "/lib/systemd/system/example.socket"
  content = <<EOF
[Unit]
Description=Example service local unix socket

[Socket]
ListenDatagram=/tmp/example-service.socket
SocketMode=0622

[Install]
WantedBy=sockets.target
EOF
}

task "install-binary" {
  interpreter = "/bin/bash"
  check = "[[ -f /usr/sbin/example-service ]]"
  apply = "cp service /usr/sbin/example-service"
}

task.query "reload-systemd" {
  query = "systemctl daemon-reload"
}

systemd.unit.state "example.service" {
  unit = "example.service"
  state = "running"
  depends = ["file.content.example.service","file.content.example.socket","task.install-binary"]
}
