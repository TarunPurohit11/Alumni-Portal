import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8080",
});

export default function Alumni() {
  const [alumni, setAlumni] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchAlumni = async () => {
      try {
        // Fetch ONLY 3 alumni (same style as Groups)
        const res = await api.get("/api/alumni/public?page=0&size=3");
        console.log(res.data);
        // Page<User> → content
        setAlumni(res.data.content || []);
      } catch (error) {
        console.error("Failed to fetch alumni", error);
      } finally {
        setLoading(false);
      }
    };

    fetchAlumni();
  }, []);

  if (loading) {
    return (
      <p className="text-center mt-10 text-gray-500">
        Loading alumni...
      </p>
    );
  }

  return (
    <section className="mt-12">
      <h2 className="text-2xl font-bold mb-6 text-gray-900 border-b-2 border-indigo-200 pb-2">
        🎓 Featured Alumni
      </h2>

      {/* ALUMNI CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {alumni.map((user) => (
          <div
            key={user.id}
            className="bg-white rounded-xl shadow-md border border-gray-200 hover:shadow-xl hover:bg-indigo-50 transition transform hover:-translate-y-1"
          >
            <div className="p-6">
              <h3 className="text-lg font-bold text-indigo-700">
                {user.name}
              </h3>

              <p className="text-sm text-gray-700 mt-1">
                {user.title || "Alumni"}
              </p>

              <p className="text-sm text-gray-600">
                {user.company || "Company not specified"}
              </p>

              {user.course && user.year && (
                <p className="text-xs text-gray-500 mt-2">
                  {user.course} • Class of {user.year}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* VIEW ALL ALUMNI */}
      <div className="mt-6 flex justify-end">
        <button
          onClick={() => navigate("/AlumniDirectory")}
          className="bg-white border-2 border-indigo-400 text-indigo-700 px-6 py-3 rounded-xl hover:bg-indigo-100 shadow-md transition font-extrabold flex items-center gap-2"
        >
          View All Alumni
          <span className="text-lg">→</span>
        </button>
      </div>
    </section>
  );
}
