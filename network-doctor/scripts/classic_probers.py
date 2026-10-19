"""Network-layer diagnostic probes for Classic Compute.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
"""

import ipaddress as _ipaddress
import socket
import ssl
import subprocess
import time

from models import CheckResult, Status


def _parse_nslookup_answers(raw):
    """Extract the ANSWER addresses from `nslookup` output.

    nslookup prints the RESOLVER it queried first ("Server:" / "Address: <dns>#53"),
    then the answer section, which always begins at the first "Name:" line. Taking
    every "Address:" line would hand back the DNS server's own IP, so only lines after
    the first "Name:" count. Handles the "Addresses: a, b" multi-value form and
    continuation lines (busybox/BIND variants).

    Returns a sorted list of unique address strings; [] when the output could not be
    parsed (caller must then degrade honestly, never guess).
    """
    if not raw:
        return []
    lines = raw.splitlines()
    first_name = -1
    for i, ln in enumerate(lines):
        if ln.strip().lower().startswith("name:"):
            first_name = i
            break
    if first_name < 0:
        return []
    found, in_addrs = [], False
    for ln in lines[first_name + 1:]:
        low = ln.strip().lower()
        if low.startswith("addresses:") or low.startswith("address:"):
            in_addrs = True
            _, _, rest = ln.partition(":")
            found.extend(a.strip() for a in rest.split(",") if a.strip())
            continue
        # Continuation lines of an "Addresses:" block are indented bare addresses.
        if in_addrs and ln.startswith((" ", "\t")) and ln.strip():
            found.extend(a.strip() for a in ln.split(",") if a.strip())
            continue
        if low.startswith("name:"):
            in_addrs = False
            continue
        if low:
            in_addrs = False
    out = set()
    for a in found:
        a = a.split("#")[0].strip()          # strip "#53" port suffixes
        if not a:
            continue
        try:
            _ipaddress.ip_address(a)
        except ValueError:
            continue
        out.add(a)
    return sorted(out)


def check_dns(host, timeout=5.0, compute_type="classic", private_link_capable=False):
    """Resolve a hostname and RECONCILE the two answers we can get for it.

    Two different questions, previously conflated:
      * `socket.getaddrinfo` = what THIS process will actually connect to. It honours
        /etc/hosts, so on a Databricks classic node the workspace hostname resolves to
        the node's OWN host-subnet NIC (the node proxies workspace traffic).
      * `nslookup` = what DNS actually says, i.e. the real address of the target (for a
        back-end-Private-Link workspace, its private-endpoint IP).

    In the field these disagreed (10.40.5.4 vs 10.40.6.8) and the check shipped
    the getaddrinfo answer as "Resolved to ...". The NSG and route checks then analysed
    the NODE'S OWN address: NSG PASSed on the host subnet's NSG while the real target
    sits in a PE subnet with no NSG at all, and the route check declared the target
    forced through the NVA when it is in-VNet.

    So: the DNS-authoritative address becomes `metadata["ips"]` (what every downstream
    infra check analyses), and the local override is surfaced as its own labelled
    observation — it is a real, useful fact about the environment, not "the resolved IP".
    When the two agree, behaviour is exactly as before. When nslookup is missing or
    unparseable we say so and degrade; we do NOT silently trust a value we have just
    learned can be the local machine.
    """
    start = time.time()
    target = host
    serverless_only = str(compute_type or "").strip().lower() == "serverless"
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old)
        local_ips = sorted({addr[4][0] for addr in results})
        ms = (time.time() - start) * 1000
        raw = ""
        nslookup_error = ""
        try:
            proc = subprocess.run(["nslookup", host], capture_output=True, text=True, timeout=timeout)
            raw = (proc.stdout + "\n" + proc.stderr).strip()
        except FileNotFoundError:
            nslookup_error = "the `nslookup` command is not available on this runtime"
        except Exception as e:
            nslookup_error = f"`nslookup` failed: {e}"
        dns_ips = _parse_nslookup_answers(raw)

        base_md = {"local_resolver_ips": local_ips, "dns_authoritative_ips": dns_ips,
                   "nslookup_error": nslookup_error}

        # (a) No usable DNS answer -> report the effective address but do NOT present it
        #     as DNS truth.
        if not dns_ips:
            why = nslookup_error or ("the `nslookup` output could not be parsed"
                                     if raw else "`nslookup` produced no output")
            return CheckResult("DNS Resolution", target, Status.WARN,
                f"Resolved to {', '.join(local_ips)} via the local resolver, but this could NOT be "
                f"confirmed against DNS ({why}). On a Databricks node the local resolver honours "
                "/etc/hosts and can return the NODE'S OWN address for the workspace hostname, so "
                "treat this address — and any NSG/route analysis based on it — as UNCONFIRMED.",
                raw_output=raw[:4096], duration_ms=ms,
                metadata=dict(base_md, ips=local_ips, resolution_source="local_resolver_only",
                              local_override=None, inconclusive=True),
                recommendation=(
                    "Confirm the target's real address from DNS before acting on the NSG/route "
                    "findings: run `nslookup " + host + "` (or `dig +short " + host + "`) on a node "
                    "in the data-plane subnet, or read the A record in Azure Portal > Private DNS "
                    "zones > the relevant privatelink zone."))

        # (b) They agree -> exactly the previous behaviour.
        if set(dns_ips) == set(local_ips):
            return CheckResult("DNS Resolution", target, Status.PASS,
                f"Resolved to {', '.join(dns_ips)}", raw_output=raw[:4096], duration_ms=ms,
                metadata=dict(base_md, ips=dns_ips, resolution_source="agreed",
                              local_override=False))

        # (c) They disagree -> DNS wins for infra analysis; the override is its own fact.
        extra = [ip for ip in local_ips if ip not in dns_ips]
        return CheckResult("DNS Resolution", target, Status.WARN,
            f"DNS resolves {host} to {', '.join(dns_ips)} — this is the address used for all "
            f"NSG / route / private-endpoint analysis. The LOCAL resolver on this node answers "
            f"{', '.join(local_ips)} instead"
            + (f" ({', '.join(extra)} is not in DNS at all)" if extra else "")
            + ", i.e. a local override (/etc/hosts or a local proxy) is in effect for this "
              "hostname. See the 'Local DNS Override' observation.",
            raw_output=raw[:4096], duration_ms=ms,
            metadata=dict(base_md, ips=dns_ips, resolution_source="dns_authoritative",
                          local_override=True, override_only_ips=extra))
    except socket.gaierror as e:
        ms = (time.time() - start) * 1000
        if serverless_only:
            if private_link_capable:
                next_layer = (
                    "This hostname maps to a Private-Link-capable Azure resource, so check the "
                    "attached NCC's private-endpoint rule and the account Network policy Egress "
                    "rules.")
            else:
                next_layer = (
                    "This hostname is handled as a public DNS destination, so check the account "
                    "Network policy > Egress rules for its DNS name.")
            recommendation = (
                "DNS resolution failed from SERVERLESS compute. Diagnose this at the "
                "serverless account layer, not in workspace-network settings. " + next_layer +
                " Also confirm the hostname is spelled correctly.")
        else:
            recommendation = (
                "DNS resolution failed. Check:\n"
                "1. Azure Private DNS Zone is linked to the Databricks VNet\n"
                "2. Custom DNS server has a conditional forwarder for this domain\n"
                "3. The hostname is spelled correctly\n"
                "4. NSG rules allow UDP/TCP port 53 (DNS)")
        return CheckResult("DNS Resolution", target, Status.FAIL,
            f"Cannot resolve hostname: {e}", duration_ms=ms,
            recommendation=recommendation)
    except Exception as e:
        return CheckResult("DNS Resolution", target, Status.ERROR,
            f"Unexpected error: {e}", duration_ms=(time.time()-start)*1000)


def check_local_dns_override(dns_result):
    """Derived observation: the local resolver disagrees with DNS for this hostname.

    Kept as a check of its OWN rather than folded into the DNS row, because it is a
    distinct fact about the environment with its own consequences: something on this
    node (an /etc/hosts entry, a local forwarder/proxy) is redirecting the hostname,
    so probes measure the proxy while the infra analysis must target the real address.

    Returns a CheckResult, or SKIP when there is nothing to report.
    """
    md = (getattr(dns_result, "metadata", None) or {}) if dns_result is not None else {}
    target = getattr(dns_result, "target", "") or "(unknown host)"
    if dns_result is None or not md:
        return CheckResult("Local DNS Override", target, Status.SKIP,
            "DNS check did not run — nothing to reconcile.")
    if md.get("local_override") is None:
        return CheckResult("Local DNS Override", target, Status.SKIP,
            "DNS could not be read independently of the local resolver, so a local override "
            "can neither be confirmed nor ruled out (see the DNS Resolution row).",
            metadata={"local_override": None, "derived_from": "dns"})
    local_ips = md.get("local_resolver_ips") or []
    dns_ips = md.get("dns_authoritative_ips") or []
    if not md.get("local_override"):
        return CheckResult("Local DNS Override", target, Status.PASS,
            f"No local override: the node's resolver and DNS agree on {', '.join(dns_ips)}.",
            metadata={"local_override": False, "local_resolver_ips": local_ips,
                      "dns_authoritative_ips": dns_ips, "derived_from": "dns"})
    return CheckResult("Local DNS Override", target, Status.WARN,
        f"This node resolves {target} to {', '.join(local_ips)} locally, while DNS answers "
        f"{', '.join(dns_ips)}. A local override (/etc/hosts entry or a local forwarder) is "
        "redirecting the hostname on this machine. Consequences: connection probes (TCP/TLS/"
        "latency) measure the path to the LOCAL address, while NSG / route / private-endpoint "
        "analysis is deliberately performed against the DNS address — the two rows are "
        "answering about different addresses on purpose. For a Databricks workspace hostname "
        "this is normal and benign: the node proxies workspace traffic through itself.",
        recommendation=(
            "No action needed if this is a Databricks workspace hostname on a Databricks node "
            "(expected). Investigate only if the hostname is a customer endpoint that should not "
            "be intercepted: check /etc/hosts and any cluster init script that writes to it, and "
            f"compare with `nslookup {target}`."),
        metadata={"local_override": True, "local_resolver_ips": local_ips,
                  "dns_authoritative_ips": dns_ips,
                  # This row is a DERIVED second view of the DNS row's fact, not an
                  # independent finding. Declaring the relationship structurally lets the
                  # customer-facing guide state the override ONCE instead of spending two
                  # paragraphs on it — and any future derived check gets the same
                  # treatment for free, without the guide knowing this check's name.
                  "derived_from": "dns",
                  "override_only_ips": md.get("override_only_ips") or []})


def check_tcp(host, port, timeout=5.0):
    """Test TCP connectivity to host:port."""
    start = time.time()
    target = f"{host}:{port}"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ms = (time.time() - start) * 1000
        local = sock.getsockname()
        sock.close()
        return CheckResult("TCP Connectivity", target, Status.PASS,
            f"Connected in {ms:.0f}ms (from {local[0]}:{local[1]})", duration_ms=ms)
    except socket.timeout:
        ms = (time.time() - start) * 1000
        return CheckResult("TCP Connectivity", target, Status.FAIL,
            f"Connection timed out after {timeout}s", duration_ms=ms,
            recommendation=(
                "TCP connection timed out -- packets are being dropped. Check:\n"
                "1. NSG outbound rules allow traffic to this IP on port {port}\n"
                "2. Route table has a route for the target (next hop: VPN/ER Gateway)\n"
                "3. Azure Firewall or NVA allows this traffic\n"
                "4. VNet peering has 'Allow Forwarded Traffic' enabled\n"
                "5. On-prem firewall allows inbound from Databricks subnet").format(port=port))
    except ConnectionRefusedError:
        ms = (time.time() - start) * 1000
        return CheckResult("TCP Connectivity", target, Status.FAIL,
            f"Connection refused -- host reachable but port {port} is closed", duration_ms=ms,
            recommendation=(
                "The host is reachable but nothing is listening on port {port}. Check:\n"
                "1. The database service is running on the target host\n"
                "2. The port number is correct\n"
                "3. Host-level firewall on the target allows this port").format(port=port))
    except OSError as e:
        ms = (time.time() - start) * 1000
        msg = str(e)
        rec = ("TCP connection failed. Check:\n"
               "1. NSG outbound rules on Databricks subnets\n"
               "2. Route table entries for the target network\n"
               "3. VNet peering configuration")
        if "No route" in msg or "unreachable" in msg.lower():
            rec = ("No network route to the target. Check:\n"
                   "1. VNet peering is Connected (both sides)\n"
                   "2. Route table has entry for target CIDR -> Virtual Network Gateway\n"
                   "3. VPN/ExpressRoute gateway is healthy\n"
                   "4. BGP route propagation is enabled")
        return CheckResult("TCP Connectivity", target, Status.FAIL,
            f"Connection failed: {msg}", duration_ms=ms, recommendation=rec)
    except Exception as e:
        return CheckResult("TCP Connectivity", target, Status.ERROR,
            f"Unexpected error: {e}", duration_ms=(time.time()-start)*1000)


def check_tls(host, port, timeout=5.0):
    """Validate TLS/SSL handshake and certificate chain."""
    start = time.time()
    target = f"{host}:{port}"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                ms = (time.time() - start) * 1000
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                expiry = cert.get("notAfter", "")
                return CheckResult("TLS Handshake", target, Status.PASS,
                    f"TLS OK -- {cipher[1] if cipher else 'unknown'}, issued by {issuer.get('organizationName', 'unknown')}",
                    duration_ms=ms,
                    metadata={"subject": subject.get("commonName",""), "issuer": issuer.get("organizationName",""),
                              "expiry": expiry, "protocol": cipher[1] if cipher else "", "cipher": cipher[0] if cipher else ""})
    except ssl.SSLCertVerificationError as e:
        ms = (time.time() - start) * 1000
        return CheckResult("TLS Handshake", target, Status.FAIL,
            f"Certificate verification failed: {e}", duration_ms=ms,
            recommendation="TLS certificate is not trusted. Common causes:\n1. Self-signed certificate -- add CA cert to cluster truststore\n2. SSL-intercepting proxy/firewall replacing certificates\n3. Expired certificate on the target server")
    except ssl.SSLError as e:
        ms = (time.time() - start) * 1000
        return CheckResult("TLS Handshake", target, Status.FAIL,
            f"TLS error: {e}", duration_ms=ms,
            recommendation="TLS handshake failed. Check:\n1. The target supports TLS on this port\n2. TLS version compatibility (TLS 1.2+ recommended)\n3. No firewall doing deep packet inspection/SSL termination")
    except Exception as e:
        return CheckResult("TLS Handshake", target, Status.FAIL, f"TLS check failed: {e}", duration_ms=(time.time()-start)*1000)


def check_traceroute(host, timeout=30):
    """Run traceroute/tracepath to identify where packets are dropped."""
    start = time.time()
    for cmd in [["traceroute", "-n", "-m", "20", "-w", "2", host], ["tracepath", "-n", host]]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            ms = (time.time() - start) * 1000
            output = proc.stdout.strip()
            if not output:
                continue
            lines = [l for l in output.split("\n") if l.strip() and not l.strip().startswith("traceroute")]
            hop_count = len(lines)
            timeout_hops = sum(1 for l in lines if "* * *" in l)
            msg = f"{hop_count} hops traced"
            if timeout_hops > hop_count * 0.5:
                msg += f" ({timeout_hops} timed out -- possible firewall blocking ICMP)"
            return CheckResult("Traceroute", host, Status.WARN, msg,
                raw_output=output[:4096], duration_ms=ms, metadata={"hops": hop_count, "timeout_hops": timeout_hops})
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return CheckResult("Traceroute", host, Status.WARN, "Traceroute timed out", duration_ms=(time.time()-start)*1000)
    return CheckResult("Traceroute", host, Status.SKIP, "traceroute/tracepath not available", duration_ms=(time.time()-start)*1000)


def check_latency(host, port, samples=10, timeout=5.0):
    """Measure TCP connection latency over multiple samples."""
    start = time.time()
    target = f"{host}:{port}"
    times = []
    for _ in range(samples):
        t0 = time.time()
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            times.append((time.time() - t0) * 1000)
        except Exception:
            pass
    if not times:
        return CheckResult("Latency", target, Status.FAIL, "All connection attempts failed", duration_ms=(time.time()-start)*1000)
    times.sort()
    avg = sum(times) / len(times)
    p95_idx = max(0, int(len(times) * 0.95) - 1)
    stats = {"min": round(times[0], 1), "avg": round(avg, 1), "max": round(times[-1], 1), "p95": round(times[p95_idx], 1), "samples": len(times)}
    if avg < 100:
        status, msg = Status.PASS, f"Avg {avg:.0f}ms, P95 {times[p95_idx]:.0f}ms -- Good"
    elif avg < 500:
        status, msg = Status.WARN, f"Avg {avg:.0f}ms, P95 {times[p95_idx]:.0f}ms -- Elevated"
    else:
        status, msg = Status.FAIL, f"Avg {avg:.0f}ms, P95 {times[p95_idx]:.0f}ms -- High latency"
    return CheckResult("Latency", target, status, msg, duration_ms=(time.time()-start)*1000, metadata=stats)


def check_ping(host, count=4, timeout=5, compute_type="classic"):
    """Send ICMP ping (informational -- ICMP is often blocked by policy)."""
    start = time.time()
    try:
        import platform, re
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        proc = subprocess.run(["ping", flag, str(count), "-W", str(timeout), host],
            capture_output=True, text=True, timeout=timeout * count + 5)
        ms = (time.time() - start) * 1000
        output = proc.stdout + proc.stderr
        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss", output)
        loss = float(loss_match.group(1)) if loss_match else 100.0
        if loss == 0:
            status, msg = Status.PASS, "Ping OK -- 0% loss"
        elif loss < 100:
            status, msg = Status.WARN, f"Ping partial -- {loss:.0f}% loss"
        else:
            status, msg = Status.WARN, "Ping failed (100% loss) -- ICMP may be blocked by policy"
        if loss > 0 and str(compute_type or "").strip().lower() == "serverless":
            recommendation = (
                "Note: ICMP/Ping is often unavailable from serverless runtimes. A failed ping "
                "is informational and does NOT mean the target is unreachable; use DNS and TCP "
                "results for the egress verdict.")
        else:
            recommendation = (
                "Note: ICMP/Ping is often blocked by Azure NSGs or firewalls. A failed ping does "
                "NOT necessarily mean the target is unreachable." if loss > 0 else "")
        return CheckResult("Ping (ICMP)", host, status, msg, raw_output=output[:4096], duration_ms=ms,
            recommendation=recommendation)
    except FileNotFoundError:
        return CheckResult("Ping (ICMP)", host, Status.SKIP, "ping not available", duration_ms=(time.time()-start)*1000)
    except Exception as e:
        return CheckResult("Ping (ICMP)", host, Status.WARN, f"Ping error: {e}", duration_ms=(time.time()-start)*1000)
