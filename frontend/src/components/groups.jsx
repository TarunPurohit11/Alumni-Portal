import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const api = axios.create({
  baseURL: "http://localhost:8080",
});

export default function Groups() {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchGroups = async () => {
      try {
        // Fetch ONLY 3 groups
        const res = await api.get("/api/groups/all?page=0&size=3");
        setGroups(res.data.content || []);
      } catch (error) {
        console.error("Failed to fetch groups", error);
      } finally {
        setLoading(false);
      }
    };

    fetchGroups();
  }, []);

  if (loading) {
    return (
      <p className="text-center mt-10 text-gray-500">
        Loading groups...
      </p>
    );
  }

  return (
    <section className="mt-12">
      <h2 className="text-2xl font-bold mb-6 text-gray-900 border-b-2 border-indigo-200 pb-2">
        👥 Tech Groups
      </h2>

      {/* GROUP CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {groups.map((group) => (
          <div
            key={group.id}
            className="bg-white rounded-xl shadow-md border border-gray-200 hover:shadow-xl hover:bg-indigo-50 transition transform hover:-translate-y-1"
          >
            <div className="p-6">
              <h3 className="text-lg font-bold text-indigo-700">
                {group.title}
              </h3>

              <p className="text-sm text-gray-600 mt-2 line-clamp-3">
                {group.description}
              </p>

              <div className="mt-4 text-xs text-gray-500">
                {group.members?.length || 0} Members
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* VIEW ALL GROUPS */}
      <div className="mt-6 flex justify-end">
        <button
          onClick={() => navigate("/tech/groups")}
          className="bg-white border-2 border-indigo-400 text-indigo-700 px-6 py-3 rounded-xl hover:bg-indigo-100 shadow-md transition font-extrabold flex items-center gap-2"
        >
          View All Groups
          <span className="text-lg">→</span>
        </button>
      </div>
    </section>
  );
}
