import React, { useState } from "react";
import axios from "axios";

const api = axios.create({ baseURL: "http://localhost:8080" });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function EventForm() {
  const [form, setForm] = useState({
    title: "",
    shortDescription: "",
    content: "",
    eventDate: "",
    imageUrl: "",
  });
  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSuccessMsg("");
    setErrorMsg("");

    try {
      setLoading(true);
      const dto = {
        title: form.title,
        shortDescription: form.shortDescription,
        content: form.content,
        eventDate: form.eventDate, // ISO date string
        imageUrl: form.imageUrl || null,
      };
      await api.post("/api/admin/create/event", dto);
      setSuccessMsg("Event added successfully!");
      setForm({ title: "", shortDescription: "", content: "", eventDate: "", imageUrl: "" });
    } catch (err) {
      setErrorMsg(err.response?.data?.message || "Failed to add event");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="bg-white p-8 rounded-lg border max-w-xl mx-auto space-y-4" onSubmit={handleSubmit}>
      <h2 className="text-lg font-semibold mb-4">Add Event</h2>

      <input
        type="text"
        name="title"
        placeholder="Title"
        className="w-full border px-3 py-2 rounded"
        value={form.title}
        onChange={handleChange}
        required
      />

      <input
        type="text"
        name="shortDescription"
        placeholder="Short Description"
        className="w-full border px-3 py-2 rounded"
        value={form.shortDescription}
        onChange={handleChange}
        required
      />

      <textarea
        name="content"
        placeholder="Content"
        className="w-full border px-3 py-2 rounded"
        value={form.content}
        onChange={handleChange}
        rows={5}
        required
      />

      <input
        type="date"
        name="eventDate"
        className="w-full border px-3 py-2 rounded"
        value={form.eventDate}
        onChange={handleChange}
        required
      />

      <input
        type="text"
        name="imageUrl"
        placeholder="Image URL (optional)"
        className="w-full border px-3 py-2 rounded"
        value={form.imageUrl}
        onChange={handleChange}
      />

      {form.imageUrl && (
        <img src={form.imageUrl} alt="Preview" className="h-32 w-32 object-cover rounded mt-2" />
      )}

      {successMsg && <p className="text-green-600">{successMsg}</p>}
      {errorMsg && <p className="text-red-600">{errorMsg}</p>}

      <button
        type="submit"
        className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
        disabled={loading}
      >
        {loading ? "Saving..." : "Add Event"}
      </button>
    </form>
  );
}
