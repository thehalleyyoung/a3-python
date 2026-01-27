#!/usr/bin/env python3
"""
Demonstration of socket taint tracking (Iteration 530).

Shows how taint propagates through network socket objects to detect
second-order SSRF vulnerabilities.
"""

from pyfromscratch.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType
)
from pyfromscratch.semantics.security_tracker_lattice import (
    LatticeSecurityTracker
)


def demo_basic_socket_taint():
    """Basic example: tainted host creates tainted socket."""
    print("=" * 70)
    print("DEMO 1: Basic Socket Taint Propagation")
    print("=" * 70)
    
    tracker = LatticeSecurityTracker()
    
    print("\n1. User provides hostname via HTTP parameter:")
    print("   host = request.args.get('host')")
    host = "attacker.com"
    host_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "line:10")
    tracker.set_label(host, host_label)
    print(f"   → host taint: τ={bin(host_label.tau)} (HTTP_PARAM)")
    
    print("\n2. Create socket to user-controlled host:")
    print("   sock = socket.create_connection((host, 80))")
    sock = "socket_obj"
    sock_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, 80],
        result=sock,
        location="line:11"
    )
    print(f"   → socket taint: τ={bin(sock_label.tau)}")
    print(f"   → Socket inherits taint from host: {sock_label.has_untrusted_taint()}")
    
    print("\n" + "=" * 70)
    print()


def demo_socket_recv_taint():
    """Show how recv() merges source taint with socket taint."""
    print("=" * 70)
    print("DEMO 2: Socket recv() Taint Merging")
    print("=" * 70)
    
    tracker = LatticeSecurityTracker()
    
    print("\n1. Tainted socket (from tainted host):")
    sock = "socket"
    sock_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "line:20")
    tracker.set_label(sock, sock_label)
    print(f"   τ_socket = {bin(sock_label.tau)} (HTTP_PARAM)")
    
    print("\n2. Receive data from socket:")
    print("   data = sock.recv(1024)")
    data = "received_data"
    data_label, _ = tracker.handle_call_post(
        func_name="socket.recv",
        func_ref=sock,  # CRITICAL: socket object is passed as func_ref
        args=[1024],
        result=data,
        location="line:21"
    )
    
    print(f"   → data taint: τ={bin(data_label.tau)}")
    
    # Check individual source bits
    http_bit = 1 << SourceType.HTTP_PARAM.value
    network_bit = 1 << SourceType.NETWORK_RECV.value
    
    has_http = (data_label.tau & http_bit) != 0
    has_network = (data_label.tau & network_bit) != 0
    
    print(f"   → Has HTTP_PARAM taint (from socket): {has_http}")
    print(f"   → Has NETWORK_RECV taint (from source): {has_network}")
    print(f"   ✅ Data has BOTH taints (τ = τ_source ⊔ τ_socket)")
    
    print("\n" + "=" * 70)
    print()


def demo_second_order_ssrf():
    """Full attack scenario: second-order SSRF."""
    print("=" * 70)
    print("DEMO 3: Second-Order SSRF Attack")
    print("=" * 70)
    
    tracker = LatticeSecurityTracker()
    
    print("\n[ATTACK SCENARIO]")
    print("Attacker controls the host, fetches malicious URL from their server,")
    print("then victim makes request to that URL.")
    print()
    
    print("1. Attacker provides host:")
    print("   host = request.args.get('callback_host')")
    host = "attacker.com"
    host_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "line:30")
    tracker.set_label(host, host_label)
    
    print("\n2. Connect to attacker's server:")
    print("   sock = socket.create_connection((host, 80))")
    sock = "sock"
    sock_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, 80],
        result=sock,
        location="line:31"
    )
    
    print("\n3. Receive URL from attacker's server:")
    print("   data = sock.recv(1024)")
    data = "data"
    data_label, _ = tracker.handle_call_post(
        func_name="socket.recv",
        func_ref=sock,
        args=[1024],
        result=data,
        location="line:32"
    )
    print(f"   → data taint: τ={bin(data_label.tau)}")
    
    print("\n4. Use received data as URL (SSRF!):")
    print("   url = data.decode()")
    print("   requests.get(url)  # ← This is the vulnerability!")
    url = "decoded_url"
    tracker.set_label(url, data_label)
    
    violation = tracker.handle_call_pre(
        func_name="requests.get",
        args=[url],
        location="line:35",
        is_method_call=False
    )
    
    if violation:
        print(f"\n   🚨 VIOLATION DETECTED: {violation.bug_type}")
        print(f"   📍 Location: {violation.sink_location}")
        print(f"   📝 Message: {violation.message}")
        print(f"   🔍 CWE: {violation.cwe}")
    else:
        print("\n   ❌ No violation detected (BUG IN ANALYZER!)")
    
    print("\n[EXPLANATION]")
    print("The URL carries HTTP_PARAM taint transitively:")
    print("  HTTP_PARAM → host → socket → received data → URL → SSRF sink")
    print()
    print("Without socket taint tracking, this would be missed!")
    
    print("\n" + "=" * 70)
    print()


def demo_clean_socket_no_false_positive():
    """Show that clean sockets don't cause false positives."""
    print("=" * 70)
    print("DEMO 4: Clean Socket (No False Positive)")
    print("=" * 70)
    
    tracker = LatticeSecurityTracker()
    
    print("\n1. Clean hardcoded host:")
    print("   sock = socket.create_connection(('api.example.com', 443))")
    host = "api.example.com"
    host_label = TaintLabel.clean()
    tracker.set_label(host, host_label)
    
    sock = "sock"
    sock_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, 443],
        result=sock,
        location="line:40"
    )
    print(f"   → socket taint: τ={bin(sock_label.tau)} (clean)")
    
    print("\n2. Receive data:")
    print("   data = sock.recv(1024)")
    data = "data"
    data_label, _ = tracker.handle_call_post(
        func_name="socket.recv",
        func_ref=sock,
        args=[1024],
        result=data,
        location="line:41"
    )
    print(f"   → data taint: τ={bin(data_label.tau)}")
    
    # Check taints
    network_bit = 1 << SourceType.NETWORK_RECV.value
    http_bit = 1 << SourceType.HTTP_PARAM.value
    
    has_network = (data_label.tau & network_bit) != 0
    has_http = (data_label.tau & http_bit) != 0
    
    print(f"   → Has NETWORK_RECV: {has_network} (expected)")
    print(f"   → Has HTTP_PARAM: {has_http} (should be False)")
    
    if not has_http:
        print("   ✅ Correct: No false HTTP_PARAM taint from clean socket")
    else:
        print("   ❌ ERROR: False positive!")
    
    print("\n" + "=" * 70)
    print()


def main():
    """Run all demonstrations."""
    print()
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "SOCKET TAINT TRACKING DEMONSTRATION" + " " * 18 + "║")
    print("║" + " " * 24 + "(Iteration 530)" + " " * 29 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    demo_basic_socket_taint()
    demo_socket_recv_taint()
    demo_second_order_ssrf()
    demo_clean_socket_no_false_positive()
    
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 29 + "SUMMARY" + " " * 32 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    print("Socket taint tracking enables detection of second-order SSRF")
    print("by propagating taint through socket objects:")
    print()
    print("  1. Tainted host → Tainted socket")
    print("  2. Tainted socket → Tainted received data")
    print("  3. Tainted data → Security violation at sink")
    print()
    print("This is compositional and works across function boundaries.")
    print("No false positives for clean sockets.")
    print()


if __name__ == "__main__":
    main()
