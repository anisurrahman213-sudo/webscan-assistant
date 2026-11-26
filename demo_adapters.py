"""
demo_adapters.py -- Offline test of the wrapping adapters (no network, no nmap).

  * SubprocessTool  driven with `echo` (prints fake nmap greppable output)
  * PythonFnTool    wrapping a trivial Python function
  * the nmap parser fed a sample greppable line

    python3 demo_adapters.py
"""
from finding import Finding, Severity
from scope import RiskLevel
from tools.adapters import SubprocessTool, PythonFnTool
from tools.port_scan import _parse as nmap_parse


def main() -> None:
    # 1) SubprocessTool via echo (stands in for a real CLI)
    fake = "Host: 10.0.0.1 ()\tPorts: 80/open/tcp//http//, 443/open/tcp//https//"
    st = SubprocessTool(
        name="echo_demo", description="echo stand-in",
        argv_template=["echo", fake], risk=RiskLevel.ACTIVE_SAFE,
        category="recon", parser=nmap_parse)
    r1 = st.run("http://example.test")
    print("SubprocessTool findings:", [f.title for f in r1.findings])
    assert len(r1.findings) == 2

    # 2) PythonFnTool wrapping a plain function (like one of your modules)
    def my_module(target, params):
        return [Finding(title="Example issue", severity=Severity.MEDIUM,
                        target=target, category="demo", module="my_module")]
    pt = PythonFnTool("my_module", "wraps a python function",
                      RiskLevel.INTRUSIVE, "demo", my_module)
    r2 = pt.run("http://example.test")
    print("PythonFnTool findings:", [f.summary() for f in r2.findings])
    assert r2.ok and len(r2.findings) == 1

    # 3) nmap parser directly
    pf = nmap_parse("http://example.test", fake, "", 0)
    print("nmap parser ports:", [f.title for f in pf])
    assert len(pf) == 2

    print("\nAdapter checks passed.")


if __name__ == "__main__":
    main()
