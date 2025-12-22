import React, { useEffect, useState } from "react";
import { useAuth } from "../../context/useAuth";
import Navbar from "../../components/Navbar";
import Tabs from "../../components/Tabs";
import UserTable from "../../components/UserTable";
import Pagination from "../../components/Pagination";
import EventForm from "../../components/EventForm";
import AnnouncementForm from "../../components/AnnouncementForm";
import UploadStudents from "../../components/UploadStudents";
import axios from "axios";

const api = axios.create({ baseURL: "http://localhost:8080" });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function AdminDashboard() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState("Users");
  const [users, setUsers] = useState([]);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const navItems = ["Users", "Events", "Announcements", "Upload"];

  /* ================= API ================= */
  const fetchUsers = async (pageNo = 0) => {
    try {
      setLoading(true);
      const res = await api.get("/api/admin/users", { params: { page: pageNo, size: 10 } });
      setUsers(res.data.content);
      setTotalPages(res.data.totalPages);
      setPage(res.data.number);
    } catch {
      setError("Failed to fetch users");
    } finally {
      setLoading(false);
    }
  };

  const toggleUser = async (selectedUser) => {
    if (!window.confirm(`${selectedUser.enabled ? "Disable" : "Enable"} this user?`)) return;
    try {
      const res = await api.put(`/api/admin/${selectedUser.id}/toggle`);
      alert(res.data.message);
      setUsers((prev) => prev.map((u) => (u.id === res.data.user.id ? res.data.user : u)));
    } catch (err) {
      alert(err.response?.data?.message || "Action failed");
    }
  };

  const deleteUser = async (id) => {
    if (!window.confirm("Delete this user permanently?")) return;
    try {
      const res = await api.delete(`/api/admin/${id}`);
      alert(res.data.message);
      setUsers((prev) => prev.filter((u) => u.id !== id));
    } catch (err) {
      alert(err.response?.data?.message || "Delete failed");
    }
  };

  useEffect(() => { fetchUsers(); }, []);

  /* ================= Render Tab Content ================= */
  const renderContent = () => {
    if (loading) {
      return (
        <div className="flex justify-center p-10">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-indigo-600 border-t-transparent" />
        </div>
      );
    }

    if (error) return <p className="text-center text-red-500">{error}</p>;

    switch (activeTab) {
      case "Users":
        return (
          <>
            <UserTable users={users} toggleUser={toggleUser} deleteUser={deleteUser} />
            <Pagination page={page} totalPages={totalPages} onPageChange={fetchUsers} />
          </>
        );
      case "Events":
        return <EventForm />;
      case "Announcements":
        return <AnnouncementForm />;
      case "Upload":
        return <UploadStudents />;
      default:
        return (
          <div className="bg-white p-10 rounded-lg border text-center text-gray-500">
            {activeTab} feature coming soon
          </div>
        );
    }
  };

  /* ================= Layout ================= */
  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      <Navbar user={user} logout={logout} />
      <Tabs items={navItems} active={activeTab} onChange={setActiveTab} />
      <main className="flex-grow p-10">{renderContent()}</main>
      <footer className="bg-gray-900 text-white text-xs text-center p-4">
        © 2024 IT Gopeshwar Alumni Portal
      </footer>
    </div>
  );
}
