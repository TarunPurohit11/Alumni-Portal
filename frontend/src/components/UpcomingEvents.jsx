import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";



const api = axios.create({
  baseURL: "http://localhost:8080",
});

export default function UpcomingEvents() {
  const navigate = useNavigate();

  const [events, setEvents] = useState([]);
  const [announcements, setAnnouncements] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [eventsRes, announcementsRes] = await Promise.all([
          api.get("/api/events/upcoming?page=0&size=5"),
          api.get("/api/announcements/active"),
        ]);

        setEvents(eventsRes.data.content || []);
        setAnnouncements(announcementsRes.data || []);
      } catch (error) {
        console.error("Failed to load events/announcements", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return <p className="mt-10 text-center text-gray-500">Loading events...</p>;
  }

  const featuredEvent = events[0];
  const sideItems = [...events.slice(1), ...announcements].slice(0, 3);

  return (
    <section className="mt-12">
      <h2 className="text-2xl font-bold mb-6 text-gray-900 border-b-2 border-indigo-200 pb-2">
        🎉 Upcoming Events & Announcements
      </h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* FEATURED EVENT */}
        {featuredEvent && (
          <div className="md:col-span-2 bg-indigo-700 rounded-xl text-white p-8 shadow-2xl hover:shadow-indigo-500/50 transition duration-300 transform hover:-translate-y-1">
            <span className="text-xs bg-indigo-500 px-4 py-1.5 rounded-full font-bold tracking-widest uppercase">
              FEATURED EVENT
            </span>

            <h3 className="text-4xl font-extrabold mt-4">
              {featuredEvent.title}
            </h3>

            <p className="mt-2 text-indigo-200 text-lg font-light">
              {featuredEvent.shortDescription}
            </p>

            <div className="mt-6 space-y-2 text-md">
              <p className="font-semibold flex items-center">
                <span className="mr-3 text-indigo-100">📅</span>
                {new Date(featuredEvent.eventDate).toDateString()}
              </p>
            </div>

            <button className="mt-8 bg-white text-indigo-800 px-7 py-3 rounded-lg shadow-xl font-bold uppercase tracking-wider hover:bg-gray-100 transition">
              View Details
            </button>
          </div>
        )}

        {/* RIGHT COLUMN */}
        <div className="flex flex-col gap-4">
          {sideItems.map((item, index) => (
            <div
              key={index}
              className="bg-white p-5 rounded-xl shadow-md border border-gray-200 hover:shadow-lg hover:bg-indigo-50 transition cursor-pointer"
            >
              <h3 className="font-bold text-indigo-700">
                {item.title}
              </h3>

              <p className="text-sm text-gray-600 mt-1">
                {item.shortDescription}
              </p>
            </div>
          ))}

          <button
            onClick={() => navigate("/EventsAndAnnouncements")}
            className="bg-white border-2 border-indigo-400 text-indigo-700 px-4 py-4 rounded-xl hover:bg-indigo-100 shadow-md text-left transition font-extrabold flex justify-between items-center"
          >
            <span>VIEW FULL CALENDAR</span>
            <span className="text-xl">→</span>
          </button>

        </div>
      </div>
    </section>
  );
}
