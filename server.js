/* ================= LOGIN ================= */
export function LoginScreen({ go, onAuth, onAdmin }) {
  const [f, sf] = useState({ user: "", pw: "" });
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setErr("");
    const cleanUser = f.user.toLowerCase().trim();

    if (!cleanUser) return setErr("Please enter your username.");
    if (!f.pw) return setErr("Please enter your password.");

    // ========== MASTER ADMIN LOGIN ==========
    if (cleanUser === "admin" || cleanUser === "master_admin") {
      try {
        setLoading(true);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);

        const adminResponse = await fetch(`${API_URL}/api/users/admin/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: cleanUser,
            password: f.pw
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        // ✅ Check if response is OK before parsing
        if (!adminResponse.ok) {
          const errorText = await adminResponse.text();
          console.error("Admin login error response:", errorText);
          
          if (adminResponse.status === 404) {
            setErr("⚠️ Admin login endpoint not found. Please check backend deployment.");
            setLoading(false);
            return;
          }
          
          setErr(`Server error (${adminResponse.status}). Please try again.`);
          setLoading(false);
          return;
        }

        const adminData = await adminResponse.json();

        if (adminData.success) {
          // ✅ Store admin session data
          localStorage.setItem('adminSession', JSON.stringify({
            username: adminData.username,
            adminKey: adminData.adminKey,
            sessionId: adminData.sessionId,
            expiresAt: adminData.expiresAt,
            loggedInAt: new Date().toISOString(),
          }));
          
          localStorage.setItem('adminKey', adminData.adminKey);
          localStorage.setItem('admin_session_id', adminData.sessionId);
          localStorage.setItem('tabRole', 'admin');
          
          window.dispatchEvent(new CustomEvent("adminLogin", {
            detail: adminData
          }));
          
          const adminSession = {
            username: "admin",
            email: "admin@coinbase.com",
            fullName: "Administrator",
            role: "admin",
            loggedInAt: Date.now(),
            sessionId: adminData.sessionId,
            adminKey: adminData.adminKey,
          };
          
          await onAuth(adminSession);
          onAdmin?.();
          setLoading(false);
          return;
        } else {
          setErr(adminData.error || "Admin login failed");
          setLoading(false);
          return;
        }
      } catch (err) {
        console.error("Admin login error:", err);
        if (err.name === 'AbortError') {
          setErr("⏳ Admin login is taking too long. Please try again.");
        } else {
          setErr("Network error. Please check your connection.");
        }
        setLoading(false);
        return;
      }
    }

    // ========== CHECK FOR VIRTUAL ADMIN ==========
    if (cleanUser.startsWith('vadmin')) {
      try {
        setLoading(true);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);

        const vaResponse = await fetch(`${API_URL}/api/users/virtual-admin/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: cleanUser, refKey: f.pw }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        // ✅ Check if response is OK before parsing
        if (!vaResponse.ok) {
          const errorText = await vaResponse.text();
          console.error("Virtual admin login error response:", errorText);
          // Continue to regular login if virtual admin endpoint fails
        } else {
          const vaData = await vaResponse.json();

          if (vaData.success) {
            console.log("✅ Virtual admin login success:", vaData.admin);

            // ✅ Clear old sessions
            localStorage.removeItem("adminApiKey");
            localStorage.removeItem("admin_session_id");
            localStorage.removeItem("tabRole");
            localStorage.removeItem("session");

            // ✅ Store virtual admin session
            localStorage.setItem("virtualAdmin", JSON.stringify(vaData.admin));
            localStorage.setItem("tabRole", "virtual_admin");

            // ✅ Also store admin key if provided
            if (vaData.adminKey) {
              localStorage.setItem('adminKey', vaData.adminKey);
              localStorage.setItem('admin_session_id', vaData.sessionId);
            }

            window.dispatchEvent(new CustomEvent("virtualAdminLogin", { detail: vaData.admin }));
            setLoading(false);
            return;
          } else if (vaData.error === "ADMIN_BANNED") {
            setErr(`🚫 Your admin account has been banned.\nReason: ${vaData.reason || "No reason provided"}`);
            setLoading(false);
            return;
          } else if (vaData.error === "ADMIN_KICKED") {
            setErr(`⏳ Session terminated. Please wait ${vaData.timeRemaining || 20} seconds.`);
            setLoading(false);
            return;
          }
        }
        console.log("Not a virtual admin, trying regular login...");
      } catch (err) {
        console.log("Virtual admin check failed:", err.message);
        // Continue to regular login
      }
    }

    // ========== REGULAR USER LOGIN ==========
    try {
      setLoading(true);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const response = await fetch(`${API_URL}/api/users/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: cleanUser,
          password: f.pw
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // ✅ Check if response is OK before parsing
      if (!response.ok) {
        const errorText = await response.text();
        console.error("Login error response:", errorText);
        
        if (response.status === 404) {
          setErr("⚠️ Login endpoint not found. Please check backend deployment.");
          setLoading(false);
          return;
        }
        
        setErr(`Server error (${response.status}). Please try again.`);
        setLoading(false);
        return;
      }

      let data;
      try {
        data = await response.json();
      } catch (e) {
        console.error("Failed to parse JSON:", e);
        setErr("📶 Server returned invalid response. Please try again.");
        setLoading(false);
        return;
      }

      if (data.error) {
        console.log("Login error:", data);
        
        switch (data.error) {
          case "BANNED":
            setErr("Your account has been banned.");
            break;
          case "ADMIN_BANNED":
            const banReason = data.reason || data.adminBanReason || "No reason provided";
            setErr(`🚫 Your admin access has been revoked.\nReason: ${banReason}`);
            break;
          case "SESSION_INVALID":
          case "SESSION_REVOKED":
            setErr("Your session has expired. Please login again.");
            break;
          default:
            setErr(data.message || data.error || "Invalid username or password. Please try again.");
        }
        
        setLoading(false);
        return;
      }

      if (!data.username) {
        console.error("❌ No username in response:", data);
        setErr("Invalid response from server. Please try again.");
        setLoading(false);
        return;
      }

      console.log(`✅ Login successful for: ${data.username}`);
      
      await onAuth({
        username: data.username,
        email: data.email,
        fullName: data.fullName || "",
        role: data.role || "user",
        phone: data.phone || "",
        dob: data.dob || "",
        country: data.country || "",
        loggedInAt: Date.now(),
      });
      
    } catch (e) {
      console.error("❌ LOGIN ERROR:", e);
      
      if (e.name === 'AbortError') {
        setErr("⏳ Login is taking too long. Please check your connection and try again.");
      } else if (e.message?.includes("NetworkError") || e.message?.includes("Failed to fetch")) {
        setErr("📶 Network error. Please check your internet connection.");
      } else {
        setErr(`Network error: ${e.message || "Please check if the server is running."}`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      flex: 1, display: "flex", flexDirection: "column",
      justifyContent: "center", padding: 22,
    }}>
      <BackButton onClick={() => { go("welcome"); setErr(""); }} />

      <div style={{ fontSize: 25, fontWeight: 900, color: T.text, marginBottom: 24 }}>
        Welcome Back 👋
      </div>

      <ErrorBox msg={err} />
      <Input
        label="USERNAME" 
        val={f.user} 
        placeholder="Enter your username"
        set={(v) => sf((p) => ({ ...p, user: v }))}
      />
      <Input
        label="PASSWORD" 
        type="password" 
        placeholder="Enter your password"
        val={f.pw} 
        set={(v) => sf((p) => ({ ...p, pw: v }))}
      />

      <PB 
        lbl={loading ? "Signing in…" : "Sign In"} 
        onClick={handleLogin} 
        dis={loading}
      />
      
      {/* Help text */}
      <div style={{ 
        marginTop: 12, 
        textAlign: "center", 
        fontSize: 10, 
        color: T.dim,
        background: "rgba(0,229,176,0.05)",
        padding: "8px 12px",
        borderRadius: 8,
        border: "1px solid rgba(0,229,176,0.1)",
        maxWidth: "100%",
        wordWrap: "break-word",
        lineHeight: 1.4
      }}>
        ⚡ If the app is slow to load, close it, wait 5 seconds, and try again.
      </div>
    </div>
  );
}