# A NixOS VM test driving nsupdated end to end: nsupdate(1) sends an RFC 2136
# update over a TCP-to-unix socket bridge into nsupdated, whose AXFRDDNS
# provider applies it to a local Knot DNS primary, and dig verifies the record.
{
  pkgs,
  nsupdated,
}:
let
  zone = "example.com";
in
{
  name = "nsupdated-axfrddns";

  nodes.machine = {
    networking.firewall.enable = false;
    networking.useDHCP = false;

    # Knot DNS serves the zone on 127.0.0.1:53 as the AXFRDDNS "primary
    # master": it answers AXFR and accepts RFC 2136 dynamic updates.
    services.knot.enable = true;
    services.knot.settings = {
      server.listen = [ "127.0.0.1@53" ];

      acl.localhost = {
        address = [ "127.0.0.1" ];
        action = [ "update" "transfer" ];
      };

      template.default.storage = "/var/lib/knot";

      zone."${zone}" = {
        file = "example.com.zone";
        acl = [ "localhost" ];
      };

      log.syslog.any = "info";
    };

    # Seed the zone before knotd starts. preStart runs as the knot user once
    # systemd has created the StateDirectory /var/lib/knot, which knotd can
    # also rewrite as it persists dynamic updates.
    systemd.services.knot.preStart = ''
      cat > /var/lib/knot/example.com.zone <<'EOF'
      $ORIGIN ${zone}.
      @ 3600 IN SOA ns.${zone}. hostmaster.${zone}. 1 3600 600 604800 3600
      @ 3600 IN NS ns.${zone}.
      ns 3600 IN A 127.0.0.1
      EOF
    '';

    environment.etc."nsupdated/creds.json".text = builtins.toJSON {
      axfrddns = {
        TYPE = "AXFRDDNS";
        master = "127.0.0.1";
      };
    };

    systemd.services.nsupdated = {
      description = "nsupdated RFC 2136 proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "knot.service" ];
      serviceConfig = {
        ExecStart = "${nsupdated}/bin/nsupdated -listen /run/nsupdated.sock -creds-file /etc/nsupdated/creds.json -creds-name axfrddns -log-level debug";
        Restart = "on-failure";
      };
    };

    # nsupdate(1) cannot talk to a Unix socket, so bridge a TCP port to
    # nsupdated's socket.
    systemd.services.socat = {
      description = "TCP-to-unix bridge to nsupdated";
      wantedBy = [ "multi-user.target" ];
      after = [ "nsupdated.service" ];
      serviceConfig = {
        ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:5353,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/run/nsupdated.sock";
        Restart = "on-failure";
      };
    };

    environment.systemPackages = [ pkgs.bind ];
  };

  testScript = ''
    start_all()

    machine.wait_for_unit("knot.service")
    machine.wait_for_unit("nsupdated.service")
    machine.wait_for_unit("socat.service")

    # The seed zone is served by knotd.
    machine.wait_until_succeeds(
      "dig @127.0.0.1 example.com SOA +short | grep -q '^ns.example.com'"
    )

    # An RFC 2136 update issued with nsupdate(1), sent through the socat bridge
    # into nsupdated and applied by the AXFRDDNS provider to knotd.
    machine.succeed(
      "printf 'server 127.0.0.1 5353\\nzone example.com.\\nupdate add www.example.com. 300 A 1.2.3.4\\nsend\\n' | nsupdate -v"
    )

    # The record is served authoritatively by knotd.
    machine.wait_until_succeeds(
      "dig @127.0.0.1 www.example.com A +short | grep -q '^1.2.3.4$'"
    )

    # And an AXFR through nsupdated reflects the update too.
    machine.wait_until_succeeds(
      "dig @127.0.0.1 -p 5353 example.com AXFR +noall +answer | grep -q 'www.example.com.\\s*300\\s*IN\\s*A\\s*1.2.3.4'"
    )
  '';
}
