import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Menu, X } from "lucide-react";
import AuthModal from "../Modals/AuthModal";
import Login from "../features/auth/Login";
import axios from "axios";
import { Client } from "@stomp/stompjs";

/* ================= AXIOS ================= */

const api = axios.create({ baseURL: "http://localhost:8080" });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

/* ================= COMPONENT ================= */

export default function Navbar() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [menuOpen, setMenuOpen] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  const stompClient = useRef(null);

  /* ================= HELPERS ================= */

  const getInitials = (name) =>
    !name ? "U" : name.substring(0, 1).toUpperCase();

  /* ================= LOAD UNREAD COUNT ================= */

  const loadUnreadCount = async () => {
  try {
    const res = await api.get("/api/messages/unread-count");
    setUnreadCount(res.data);
  } catch (err) {
    console.error("Failed to load unread count:", err);
  }
};

  /* ================= WEBSOCKET ================= */

  const connectWebSocket = () => {
    if (!user) return;

    stompClient.current = new Client({
      brokerURL: "ws://localhost:8080/ws-chat/websocket",
      reconnectDelay: 5000,

      onConnect: () => {
        stompClient.current.subscribe(
          `/user/${user.id}/queue/messages`,
          () => {
            // 🔴 increment unread count instantly
            setUnreadCount((prev) => prev + 1);
          }
        );
      }
    });

    stompClient.current.activate();
  };

  /* ================= EFFECT ================= */

  useEffect(() => {
    if (user) {
      loadUnreadCount();
      connectWebSocket();
    }

    return () => {
      if (stompClient.current) {
        stompClient.current.deactivate();
      }
    };
  }, [user]);

  /* ================= UI ================= */

  return (
    <>
      <header className="w-full bg-white/80 backdrop-blur-xl border-b border-gray-200 sticky top-0 z-40 shadow-sm">
        <div className="flex justify-between items-center px-6 md:px-16 py-4">

          {/* Logo */}
          <h1
            onClick={() => navigate("/")}
            className="text-2xl md:text-3xl font-bold text-indigo-600 cursor-pointer tracking-tight"
          >
            ITG Alumni
          </h1>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-10 text-[15px] font-medium text-gray-700">

            <NavItem title="Home" href="/" />

            {!user && (
              <button
                onClick={() => setAuthModalOpen(true)}
                className="px-5 py-2 bg-indigo-600 text-white rounded-full shadow-sm 
                           hover:bg-indigo-700 transition font-semibold"
              >
                Sign In
              </button>
            )}

            {user && user.role !== "ADMIN" && (
              <>
                <button
                  onClick={() => {
                    navigate("/messages");
                    setUnreadCount(0);
                  }}
                  className="relative hover:text-indigo-600 transition"
                >
                  Messages
                  {unreadCount > 0 && (
                    <span className="absolute -top-2 -right-3 bg-red-500 text-white text-xs
                                     px-2 py-0.5 rounded-full font-bold">
                      {unreadCount}
                    </span>
                  )}
                </button>

                <div className="relative">
                  <div
                    className="flex items-center gap-2 cursor-pointer"
                    onClick={() => setDropdownOpen(!dropdownOpen)}
                  >
                    <div className="w-10 h-10 rounded-full bg-indigo-600 flex items-center justify-center text-white font-bold shadow">
                      {getInitials(user.username)}
                    </div>
                    <span className="text-gray-800 font-semibold">
                      {user.username}
                    </span>
                  </div>

                  {dropdownOpen && (
                    <div className="absolute right-0 mt-3 w-48 bg-white border border-gray-200 
                                    shadow-xl rounded-xl py-2">
                      <button
                        onClick={() => navigate("/profile")}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100"
                      >
                        Profile
                      </button>
                      <button
                        onClick={logout}
                        className="w-full text-left px-4 py-2 text-red-600 hover:bg-gray-100"
                      >
                        Logout
                      </button>
                    </div>
                  )}
                </div>
              </>
            )}

            {user && user.role === "ADMIN" && (
              <>
                <button
                  onClick={() => navigate("/admin")}
                  className="px-5 py-2 bg-emerald-700 text-white rounded-full font-semibold 
                            shadow-sm hover:bg-emerald-800 transition"
                >
                  Admin Panel
                </button>

                <button
                  onClick={logout}
                  className="px-4 py-2 bg-white text-gray-800 border border-gray-300 
                            rounded-full font-semibold shadow-sm hover:bg-gray-100 transition"
                >
                  Logout
                </button>
              </>
            )}
          </nav>

          <div className="md:hidden">
            {menuOpen ? (
              <X size={30} onClick={() => setMenuOpen(false)} />
            ) : (
              <Menu size={30} onClick={() => setMenuOpen(true)} />
            )}
          </div>
        </div>

        {menuOpen && (
          <div className="md:hidden bg-white border-t border-gray-200 px-6 py-4 flex flex-col gap-4 shadow-lg">

            <MobileItem title="Home" onClick={() => navigate("/")} />

            {!user && (
              <button
                onClick={() => {
                  setAuthModalOpen(true);
                  setMenuOpen(false);
                }}
                className="px-6 py-2 bg-indigo-600 text-white rounded-full font-semibold"
              >
                Sign In
              </button>
            )}

            {user && (
              <>
                <button
                  onClick={() => {
                    navigate("/messages");
                    setUnreadCount(0);
                  }}
                  className="relative text-gray-700 font-semibold"
                >
                  Messages
                  {unreadCount > 0 && (
                    <span className="absolute -top-2 -right-3 bg-red-500 text-white text-xs 
                                     px-2 py-0.5 rounded-full">
                      {unreadCount}
                    </span>
                  )}
                </button>

                <button
                  onClick={logout}
                  className="px-4 py-2 bg-red-500 text-white rounded-full mt-3"
                >
                  Logout
                </button>
              </>
            )}
          </div>
        )}
      </header>

      <AuthModal isOpen={authModalOpen} onClose={() => setAuthModalOpen(false)}>
        <Login />
      </AuthModal>
    </>
  );
}

/* ================= HELPERS ================= */

function NavItem({ title, href }) {
  return (
    <a href={href} className="relative group hover:text-indigo-600 transition">
      {title}
      <span className="absolute left-0 -bottom-1 h-[2px] w-0 bg-indigo-600 group-hover:w-full transition-all duration-300" />
    </a>
  );
}

function MobileItem({ title, onClick }) {
  return (
    <button onClick={onClick} className="text-gray-700 font-semibold text-left">
      {title}
    </button>
  );
}
