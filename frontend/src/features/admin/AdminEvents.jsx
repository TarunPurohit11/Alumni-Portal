import React from "react";
import "./AdminDashboard.css";

export default function AdminEvents() {
  const events = [
    { id: 1, title: "Tech Meetup 2025", status: "Pending" },
    { id: 2, title: "AI Workshop", status: "Approved" },
  ];

  return (
    <div className="admin-page">
      <h1>🗓️ Manage Events</h1>
      <p>Approve or reject submitted events.</p>

      <table className="data-table">
        <thead>
          <tr>
            <th>Event</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{event.title}</td>
              <td>{event.status}</td>
              <td>
                {event.status === "Pending" ? (
                  <>
                    <button>Approve</button>
                    <button className="danger">Reject</button>
                  </>
                ) : (
                  <button className="disabled-btn">Approved</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
