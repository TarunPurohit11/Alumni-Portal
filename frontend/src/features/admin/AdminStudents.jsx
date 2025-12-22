
import React, { useState } from "react";
import "./AdminDashboard.css";

export default function AdminStudents() {
  const [file, setFile] = useState(null);

  const handleFileChange = (e) => setFile(e.target.files[0]);
  const handleUpload = () => {
    if (!file) return alert("Please select an Excel file.");
    alert(`File "${file.name}" uploaded successfully (mock).`);
  };

  return (
    <div className="admin-page">
      <h1>🎓 Manage Students</h1>
      <p>Upload, edit, or remove student records using Excel files.</p>

      <div className="upload-section">
        <input type="file" accept=".xlsx, .xls" onChange={handleFileChange} />
        <button onClick={handleUpload}>Upload Excel</button>
      </div>

      <div className="table-placeholder">
        <p>📋 Student records table will appear here after upload.</p>
      </div>
    </div>
  );
}
