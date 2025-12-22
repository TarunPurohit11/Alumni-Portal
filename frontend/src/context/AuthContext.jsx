// src/context/AuthContext.jsx
import React, { createContext, useState, useEffect } from "react";
import jwtDecode from "jwt-decode";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  // 1. Initialize isLoading state as true
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true); // <-- NEW STATE

  useEffect(() => {
    const checkAuth = () => {
      const token = localStorage.getItem("token");
      const role = localStorage.getItem("role");

      if (token && token.split(".").length === 3) {
        try {
          const decoded = jwtDecode(token);
          // Optional: Add token expiration check here if needed
          setUser({
            username: decoded.sub,
            role: role
          });
        } catch (err) {
          console.error("Invalid JWT:", err);
          localStorage.removeItem("token");
          // user remains null
        }
      }
      
      // 2. Set loading to false once the check is complete (regardless of finding a token)
      setIsLoading(false); // <-- CRITICAL FIX
    };

    checkAuth();
  }, []);

  const login = (token, role) => {
    try {
      localStorage.setItem("token", token);
      localStorage.setItem("role", role);
      const decoded = jwtDecode(token);
      setUser({
        username: decoded.sub,
        role: role
      });
    } catch (err) {
      console.error("Cannot decode JWT:", err);
    }
  };

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role"); // Good practice to remove role too
    setUser(null);
  };

  // 3. Provide isLoading in the context value
  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout }}> 
      {children}
    </AuthContext.Provider>
  );
};

// Optional hook for cleaner consumption
export const useAuth = () => {
    return React.useContext(AuthContext);
};