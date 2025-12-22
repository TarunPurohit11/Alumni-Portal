import React, { useState } from "react";
import "./AdminDashboard.css";

export default function AdminAnnouncements() {
  const [announcements, setAnnouncements] = useState([
    { id: 1, title: "Welcome Batch 2025!", date: "2025-10-01" },
  ]);
  const [newAnn, setNewAnn] = useState("");

  const handleAdd = () => {
    if (!newAnn.trim()) return;
    setAnnouncements([
      ...announcements,
      { id: Date.now(), title: newAnn, date: new Date().toISOString().split("T")[0] },
    ]);
    setNewAnn("");
  };

  return (
    <div className="admin-page">
      <h1>📢 Announcements</h1>
      <p>Create or edit announcements visible to all users.</p>

      <div className="announcement-form">
        <input
          type="text"
          placeholder="Enter announcement..."
          value={newAnn}
          onChange={(e) => setNewAnn(e.target.value)}
        />
        <button onClick={handleAdd}>Post</button>
      </div>

      <ul className="announcement-list">
        {announcements.map((a) => (
          <li key={a.id}>
            <strong>{a.title}</strong> <span>📅 {a.date}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
