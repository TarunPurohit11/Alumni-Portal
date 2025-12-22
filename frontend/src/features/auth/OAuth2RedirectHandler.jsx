import { useEffect, useRef } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useContext } from "react";
import { AuthContext } from "../../context/AuthContext";

export default function OAuth2RedirectHandler() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useContext(AuthContext);

  // 👈 Add a ref to prevent multiple logins
  const hasRedirected = useRef(false);

  useEffect(() => {
    if (hasRedirected.current) return; // stop multiple executions
    hasRedirected.current = true;

    const token = searchParams.get("token");
    const role = searchParams.get("role");

    console.log("OAuth redirect params:", { token, role });

    if (!token || !role) {
      navigate("/login", { replace: true });
      return;
    }

    login(token,role); // save token & user info

    switch (role) {
      case "STUDENT":
        navigate("/student/dashboard", { replace: true });
        break;
      case "ALUMNI":
        navigate("/alumni/dashboard", { replace: true });
        break;
      case "ADMIN":
        navigate("/admin/dashboard", { replace: true });
        break;
      default:
        navigate("/unauthorized", { replace: true });
    }
  }, [searchParams, navigate, login]);

  return <p>Redirecting...</p>;
}
