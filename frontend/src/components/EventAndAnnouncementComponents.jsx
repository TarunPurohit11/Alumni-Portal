import React, { useEffect, useState } from "react";

const EventAndAnnouncementComponents = () => {

    // ---------------- STATE ----------------
    const [upcomingEvents, setUpcomingEvents] = useState([]);
    const [announcements, setAnnouncements] = useState([]);
    const [pastEvents, setPastEvents] = useState([]);

    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Pagination
    const [upcomingPage, setUpcomingPage] = useState(0);
    const [upcomingTotalPages, setUpcomingTotalPages] = useState(1);

    const [pastPage, setPastPage] = useState(0);
    const [pastTotalPages, setPastTotalPages] = useState(1);

    // ---------------- FETCHING ----------------
    useEffect(() => {
        fetchAllData();
    }, [upcomingPage, pastPage]);

    const fetchAllData = async () => {
        try {
            setLoading(true);

            const [upcomingRes, announcementsRes, pastRes] = await Promise.all([
                fetch(`http://localhost:8080/api/events/upcoming?page=${upcomingPage}&size=3`),
                fetch(`http://localhost:8080/api/announcements/active`),
                fetch(`http://localhost:8080/api/events/past?page=${pastPage}&size=8`)
            ]);

            const upcomingData = await upcomingRes.json();
            const announcementsData = await announcementsRes.json();
            const pastData = await pastRes.json();

            setUpcomingEvents(upcomingData.content);
            setUpcomingTotalPages(upcomingData.totalPages);

            setAnnouncements(announcementsData);

            setPastEvents(pastData.content);
            setPastTotalPages(pastData.totalPages);

        } catch (err) {
            console.error(err);
            setError("Failed to load data.");
        } finally {
            setLoading(false);
        }
    };

    if (loading) return <p className="text-center py-20">Loading...</p>;
    if (error) return <p className="text-center text-red-600">{error}</p>;

    // ---------------- UI SUB COMPONENTS ----------------

    const EventCard = ({ event }) => (
    <div className="p-6 rounded-xl shadow-lg bg-white hover:shadow-2xl transition">

        {/* EVENT BANNER IMAGE */}
        {event.imageUrl && (
            <img
                src={event.imageUrl}
                alt={event.title}
                className="w-full h-48 object-cover rounded-lg mb-4"
            />
        )}

        {/* TITLE */}
        <h3 className="text-2xl font-bold text-gray-900 mb-2">
            {event.title}
        </h3>

        {/* SHORT DESCRIPTION */}
        <p className="text-gray-600 mb-2">
            {event.shortDescription}
        </p>

        {/* EVENT DATE */}
        <p className="text-indigo-600 font-medium mb-3">
            📅 {event.eventDate}
        </p>

        {/* OPTIONAL CONTENT PREVIEW */}
        {event.content && (
            <p className="text-gray-700 text-sm line-clamp-3">
                {event.content}
            </p>
        )}
    </div>
);


    const AnnouncementItem = ({ ann }) => (
        <div className="border-b border-gray-200 py-4 last:border-b-0">
            <div className="flex justify-between items-start mb-1">
                <span className="text-xs font-semibold uppercase tracking-wider text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-full">
                    Announcement
                </span>
                <span className="text-sm text-gray-500">{ann.publishedAt}</span>
            </div>
            <h4 className="text-lg font-bold text-gray-900">{ann.title}</h4>
            <p className="text-gray-600 text-sm">{ann.shortDescription}</p>
        </div>
    );

    const PastEventCard = ({ event }) => (
    <div className="bg-white p-4 rounded-lg shadow-md hover:shadow-lg transition">

        {/* IMAGE */}
        {event.imageUrl && (
            <img
                src={event.imageUrl}
                alt={event.title}
                className="w-full h-40 object-cover rounded-lg mb-3"
            />
        )}

        {/* DATE */}
        <p className="text-xs text-gray-500 mb-1">
            📅 {event.eventDate}
        </p>

        {/* TITLE */}
        <h4 className="text-lg font-semibold text-gray-900 mb-1">
            {event.title}
        </h4>

        {/* SHORT DESCRIPTION */}
        <p className="text-gray-600 text-sm mb-2">
            {event.shortDescription}
        </p>

        {/* CONTENT PREVIEW */}
        {event.content && (
            <p className="text-gray-700 text-xs line-clamp-2">
                {event.content}
            </p>
        )}
    </div>
);

    const Pagination = ({ page, total, setPage }) => (
        <div className="flex justify-center items-center space-x-2 mt-8">
            <button
                onClick={() => setPage(page - 1)}
                disabled={page === 0}
                className={`px-4 py-2 rounded-lg ${
                    page === 0 ? "bg-gray-200 text-gray-500" : "bg-indigo-500 text-white"
                }`}
            >
                Previous
            </button>
            <span>Page {page + 1} of {total}</span>
            <button
                onClick={() => setPage(page + 1)}
                disabled={page + 1 === total}
                className={`px-4 py-2 rounded-lg ${
                    page + 1 === total ? "bg-gray-200 text-gray-500" : "bg-indigo-500 text-white"
                }`}
            >
                Next
            </button>
        </div>
    );

    // ---------------- FINAL UI ----------------

    return (
        <section className="py-16 bg-gray-50">
            <div className="container mx-auto px-6 max-w-7xl">

                {/* ---------------- HEADER ---------------- */}
                <div className="text-center mb-12">
                    <h2 className="text-4xl font-extrabold text-gray-900 mb-2">
                        Campus Pulse: Events & News
                    </h2>
                    <p className="text-xl text-gray-600">
                        Stay updated on workshops, meetups, and announcements.
                    </p>
                </div>

                {/* ---------------- UPCOMING EVENTS + ANNOUNCEMENTS ---------------- */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-20">

                    {/* UPCOMING EVENTS (2/3 width) */}
                    <div className="lg:col-span-2 space-y-8">
                        <h3 className="text-2xl font-bold text-indigo-700 border-b-2 border-indigo-200 pb-2">
                            Upcoming Events
                        </h3>

                        {upcomingEvents.map(event => (
                            <EventCard key={event.id} event={event} />
                        ))}

                        <Pagination
                            page={upcomingPage}
                            total={upcomingTotalPages}
                            setPage={setUpcomingPage}
                        />
                    </div>

                    {/* ANNOUNCEMENTS (Scrollable sidebar) */}
                    <div className="bg-white p-6 max-h-140 rounded-xl shadow-lg">
                        <h3 className="text-2xl font-bold text-gray-900 border-b pb-2 mb-4">
                            Recent Announcements
                        </h3>

                        <div className="max-h-110 overflow-y-auto pr-2 custom-scrollbar">
                            <style jsx>{`
                                .custom-scrollbar::-webkit-scrollbar { width: 8px; }
                                .custom-scrollbar::-webkit-scrollbar-thumb { background-color: #a5b4fc; }
                                .custom-scrollbar::-webkit-scrollbar-track { background: #f1f5f9; }
                            `}</style>

                            <div className="space-y-3">
                                {announcements.map(ann => (
                                    <AnnouncementItem key={ann.id} ann={ann} />
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* ---------------- PAST EVENTS SECTION ---------------- */}
                <div className="pt-10 border-t">
                    <h2 className="text-4xl font-extrabold text-center text-gray-900 mb-10">
                        Archive: Past Events & Recaps
                    </h2>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                        {pastEvents.map(event => (
                            <PastEventCard key={event.id} event={event} />
                        ))}
                    </div>

                    <Pagination
                        page={pastPage}
                        total={pastTotalPages}
                        setPage={setPastPage}
                    />
                </div>
            </div>
        </section>
    );
};

export default EventAndAnnouncementComponents;
