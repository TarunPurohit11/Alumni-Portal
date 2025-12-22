import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/useAuth";

export default function Login() {
  const [userType, setUserType] = useState("alumni");

  return (
    <div className="flex justify-center bg-white w-full">
      <div className="flex items-center justify-center px-6 py-6">
        <div className="bg-white w-full max-w-sm border border-indigo-100 rounded-xl shadow-sm p-6">
          <h1 className="text-2xl font-semibold text-indigo-800 text-center">
            ITG Portal
          </h1>
          <p className="text-sm text-indigo-500 text-center mt-1">
            Sign in to continue
          </p>

          {/* Tabs */}
          <div className="flex gap-2 bg-indigo-100/60 p-1 rounded-lg mt-6">
            <button
              onClick={() => setUserType("alumni")}
              className={`w-1/2 py-2 text-sm font-medium rounded-md transition ${
                userType === "alumni"
                  ? "bg-indigo-600 text-white"
                  : "text-indigo-700 hover:bg-indigo-200"
              }`}
            >
              Alumni
            </button>

            <button
              onClick={() => setUserType("student")}
              className={`w-1/2 py-2 text-sm font-medium rounded-md transition ${
                userType === "student"
                  ? "bg-indigo-600 text-white"
                  : "text-indigo-700 hover:bg-indigo-200"
              }`}
            >
              Student
            </button>
          </div>

          {/* Form */}
          <div className="mt-6">
            {userType === "alumni" ? <AlumniLoginForm /> : <StudentLoginForm />}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ================================================================
   Alumni Login
================================================================ */
function AlumniLoginForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const loginWithLinkedIn = async () => {
    await fetch("http://localhost:8080/auth/clear", { method: "GET", credentials: "include" });
    window.location.href = "http://localhost:8080/oauth2/authorization/linkedin";
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8080/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) throw new Error("Invalid username or password");
      const data = await res.json();

      login(data.token, data.role); // set context
      // redirect
      switch (data.role) {
        case "STUDENT":
          navigate("/student/dashboard");
          break;
        case "ALUMNI":
          navigate("/alumni/dashboard");
          break;
        case "ADMIN":
          navigate("/admin/dashboard");
          break;
        default:
          navigate("/"); // fallback
      }
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <button
        onClick={loginWithLinkedIn}
        className="w-full flex items-center justify-center gap-2 py-2 border border-indigo-200 rounded-md text-sm font-medium text-indigo-700 hover:bg-indigo-50 transition"
      >
        <img src="/linkedin.png" className="h-4 w-4" />
        Continue with LinkedIn
      </button>

      <Divider />

      <form className="space-y-3" onSubmit={handleSubmit}>
        <Input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <Input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <SubmitButton loading={loading} />
      </form>
    </div>
  );
}

/* ================================================================
   Student Login
================================================================ */
function StudentLoginForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const loginWithGoogle = async () => {
    await fetch("http://localhost:8080/auth/clear", { method: "GET", credentials: "include" });
    window.location.href = "http://localhost:8080/oauth2/authorization/google";
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8080/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) throw new Error("Invalid username or password");
      const data = await res.json();

      login(data.token, data.role); // set context
      navigate("/dashboard");       // redirect
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <button
        onClick={loginWithGoogle}
        className="w-full flex items-center justify-center gap-2 py-2 border border-indigo-200 rounded-md text-sm font-medium text-indigo-700 hover:bg-indigo-50 transition"
      >
        <img src="/google.png" className="h-4 w-4" />
        Continue with Google
      </button>

      <Divider />

      <form className="space-y-3" onSubmit={handleSubmit}>
        <Input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <Input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <SubmitButton loading={loading} />
      </form>
    </div>
  );
}

/* ================================================================
   Reusable Components
================================================================ */
function Input({ placeholder, value, onChange, type = "text" }) {
  return (
    <input
      type={type}
      required
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      className="w-full px-3 py-2 border border-indigo-200 rounded-md text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition"
    />
  );
}

function SubmitButton({ loading }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="w-full py-2 bg-indigo-600 text-white text-sm font-medium rounded-md hover:bg-indigo-700 transition disabled:opacity-50"
    >
      {loading ? "Logging in..." : "Login"}
    </button>
  );
}

function Divider() {
  return (
    <div className="my-4 flex items-center">
      <div className="flex-grow border-t border-indigo-100"></div>
      <span className="px-2 text-xs text-indigo-500">or</span>
      <div className="flex-grow border-t border-indigo-100"></div>
    </div>
  );
}
