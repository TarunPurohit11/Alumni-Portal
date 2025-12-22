import React, { useState } from "react";
import axios from "axios";
import { UploadCloud, FileSpreadsheet, CheckCircle, XCircle } from "lucide-react";

const api = axios.create({ baseURL: "http://localhost:8080" });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function UploadStudents() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setSuccessMsg("");
    setErrorMsg("");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return setErrorMsg("Please select an Excel file");

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      setSuccessMsg("");
      setErrorMsg("");
      await api.post("/api/admin/upload/students", formData);
      setSuccessMsg("Students uploaded successfully");
      setFile(null);
    } catch (err) {
      setErrorMsg(err.response?.data?.message || "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-white rounded-xl shadow border p-8">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 flex items-center justify-center rounded-lg bg-indigo-100">
            <UploadCloud className="h-5 w-5 text-indigo-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Upload Students</h2>
            <p className="text-sm text-gray-500">
              Import student profiles using an Excel file
            </p>
          </div>
        </div>

        {/* Upload Area */}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="border-2 border-dashed rounded-lg p-6 text-center hover:border-indigo-400 transition">
            <input
              type="file"
              accept=".xlsx,.xls"
              onChange={handleFileChange}
              className="hidden"
              id="file-upload"
            />
            <label htmlFor="file-upload" className="cursor-pointer">
              <FileSpreadsheet className="mx-auto h-10 w-10 text-gray-400 mb-3" />
              <p className="text-sm text-gray-600">
                <span className="font-medium text-indigo-600">Click to upload</span> or drag & drop
              </p>
              <p className="text-xs text-gray-400 mt-1">Excel files only (.xlsx, .xls)</p>
            </label>
          </div>

          {/* Selected File */}
          {file && (
            <div className="flex items-center gap-2 text-sm text-gray-700 bg-gray-50 border rounded-md px-4 py-2">
              <FileSpreadsheet className="h-4 w-4 text-green-600" />
              <span className="flex-1 truncate">{file.name}</span>
            </div>
          )}

          {/* Messages */}
          {successMsg && (
            <div className="flex items-center gap-2 text-green-700 bg-green-50 border border-green-200 rounded-md px-4 py-2">
              <CheckCircle className="h-4 w-4" />
              <span>{successMsg}</span>
            </div>
          )}

          {errorMsg && (
            <div className="flex items-center gap-2 text-red-700 bg-red-50 border border-red-200 rounded-md px-4 py-2">
              <XCircle className="h-4 w-4" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Action */}
          <button
            type="submit"
            disabled={loading}
            className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-lg font-medium text-white
              ${loading ? "bg-indigo-400 cursor-not-allowed" : "bg-indigo-600 hover:bg-indigo-700"}
            `}
          >
            {loading && (
              <svg
                className="animate-spin h-4 w-4"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
              </svg>
            )}
            {loading ? "Uploading..." : "Upload Students"}
          </button>
        </form>
      </div>
    </div>
  );
}
