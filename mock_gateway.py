"""Minimal OmniRoute-shaped gateway so the deliberation loop can be tested for real."""
import json, random, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
CALLS = {"n": 0}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj, code=200):
        b=json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/health"): return self._send({"status":"healthy"})
        return self._send({"data":[{"id":"mock-reasoner"},{"id":"mock-coder"}]})
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); body=json.loads(self.rfile.read(n) or b"{}")
        CALLS["n"]+=1
        user=" ".join(str(m.get("content","")) for m in body.get("messages",[]))
        time.sleep(0.05)
        if "restated_goal" in user:
            c=json.dumps({"restated_goal":"deliver the thing","deliverable":"a written artefact",
                "assumptions":["scope is as stated"],"unknowns":["budget"],
                "acceptance_criteria":["covers all stated points","no unsupported claims"],"risks":["scope creep"]})
        elif "rejected_alternatives" in user:
            c=json.dumps({"approach":"do it in three steps","steps":["gather","draft","check"],
                "rejected_alternatives":[{"option":"skip review","why_not":"quality risk"}],"needs_tools":[]})
        elif "hostile expert reviewer" in user:
            # reject the first critique to force a REVISE pass, accept afterwards
            if CALLS["n"] % 2 == 0:
                c=json.dumps({"verdict":"revise","severity":"major",
                    "issues":[{"problem":"no acceptance mapping","why_it_matters":"unverifiable","fix":"map each criterion"}],
                    "missing":["criterion coverage table"]})
            else:
                c=json.dumps({"verdict":"accept","severity":"none","issues":[],"missing":[]})
        elif "Rewrite the deliverable" in user:
            c="REVISED DELIVERABLE\n- criterion 1: satisfied\n- criterion 2: satisfied\nFull content follows."
        else:
            c="DRAFT DELIVERABLE\nSection 1 ...\nSection 2 ...\nOpen question: none."
        self._send({"model":"mock-reasoner","choices":[{"message":{"role":"assistant","content":c}}],
                    "usage":{"prompt_tokens":120,"completion_tokens":len(c)//4,"total_tokens":120+len(c)//4}})
if __name__=="__main__":
    ThreadingHTTPServer(("127.0.0.1",9000),H).serve_forever()
