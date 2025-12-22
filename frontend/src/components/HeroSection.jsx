import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from "../context/AuthContext";

import AuthModal from "../Modals/AuthModal";
import Login from "../features/auth/Login";

export default function HeroSection() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [authType, setAuthType] = useState("alumni");

  const openAuthModal = (type) => {
    setAuthType(type);
    setIsAuthOpen(true);
  };

  const closeAuthModal = () => setIsAuthOpen(false);

  const getDashboardRoute = () => {
    if (!user) return "/login";

    switch (user.role) {
      case "STUDENT": return "/student/dashboard";
      case "ALUMNI": return "/alumni/dashboard";
      case "ADMIN": return "/admin/dashboard";
      default: return "/login";
    }
  };

  return (
    <>
      {/* Auth Popup */}
      <AuthModal isOpen={isAuthOpen} onClose={closeAuthModal}>
        <Login defaultType={authType} />
      </AuthModal>

      <section
        className="relative h-[450px] flex items-center justify-center text-center text-white"
        style={{
          backgroundImage:
            "url('http://googleusercontent.com/image_collection/image_retrieval/7414123728644790276')",
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      >
        <div className="absolute inset-0 bg-indigo-900/80 backdrop-blur-sm"></div>

        <div className="relative z-10 p-4">

          <div className="mb-4 px-4 py-1.5 inline-block bg-white/10 rounded-full text-sm font-medium border border-indigo-500">
            * Welcome back, ITG Alumni!
          </div>

          <h1 className="text-5xl md:text-7xl font-bold">
            Institute of Technology
            <span className="block text-indigo-300 mt-2">Gopeshwar</span>
          </h1>

          <p className="mt-4 text-gray-200 max-w-2xl mx-auto text-lg">
            Join our exclusive network of graduates. Reconnect, find mentors, stay updated.
          </p>

          <div className="mt-8 flex justify-center space-x-4">

            {user ? (
              <button
                onClick={() => navigate(getDashboardRoute())}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-10 py-3 rounded-xl shadow-lg"
              >
                Go to Dashboard
              </button>
            ) : (
              <>
                <button
                  onClick={() => openAuthModal("alumni")}
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-8 py-3 rounded-xl shadow-lg"
                >
                  Login
                </button>

                <button
                  onClick={() => openAuthModal("student")}
                  className="bg-white text-indigo-700 hover:bg-indigo-100 px-8 py-3 rounded-xl border border-indigo-600 shadow"
                >
                  Register
                </button>
              </>
            )}

          </div>
        </div>
      </section>
    </>
  );
}
