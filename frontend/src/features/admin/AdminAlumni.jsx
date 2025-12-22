import React from "react";
import "./AdminDashboard.css";

export default function AdminAlumni() {
  const alumniList = [
    { id: 1, name: "Aarav Mehta", verified: false },
    { id: 2, name: "Riya Sharma", verified: true },
    { id: 3, name: "Vikram Singh", verified: false },
  ];

  return (
    <div className="admin-page">
      <h1>👨‍🎓 Manage Alumni</h1>
      <p>Approve alumni accounts linked via LinkedIn verification.</p>

      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {alumniList.map((alum) => (
            <tr key={alum.id}>
              <td>{alum.name}</td>
              <td>{alum.verified ? "✅ Verified" : "❌ Pending"}</td>
              <td>
                {alum.verified ? (
                  <button className="disabled-btn">Approved</button>
                ) : (
                  <button>Approve</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
