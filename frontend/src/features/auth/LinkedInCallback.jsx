import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

export default function LinkedInCallback() {
  const navigate = useNavigate();
  const { loginWithToken } = useAuth();

  useEffect(() => {
    // Extract ?token=... from URL
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");

    if (token) {
      loginWithToken(token);
      navigate("/alumni/dashboard"); // redirect to alumni dashboard
    } else {
      navigate("/login");
    }
  }, [navigate, loginWithToken]);

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h2>Completing your LinkedIn login...</h2>
      <p>Please wait while we redirect you to your dashboard.</p>
    </div>
  );
}
