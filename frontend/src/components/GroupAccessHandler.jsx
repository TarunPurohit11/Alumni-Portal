// src/features/group/GroupAccessHandler.jsx
import axios from "axios";
import { useNavigate } from "react-router-dom";

const api = axios.create({ baseURL: "http://localhost:8080" });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function useGroupAccessHandler() {
  const navigate = useNavigate();

  const handleGroupClick = async (groupId) => {
    try {
      // 1️⃣ Check access
      const res = await api.get(`/api/groups/${groupId}/access`);
      const { allowed, requireAssessment } = res.data;

      if (!allowed) {
        alert("You do not have access to this group yet.");
        return;
      }

      if (requireAssessment) {
        // Redirect to assessment page
        navigate(`/groups/${groupId}/assessment`);
        return;
      }

      // Otherwise, redirect to group dashboard
      navigate(`/groups/${groupId}/view`);
    } catch (err) {
      console.error("Failed to check access:", err);
      alert("Error checking group access");
    }
  };

  return { handleGroupClick };
}
