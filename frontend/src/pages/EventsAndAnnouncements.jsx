// src/pages/EventsAndAnnouncementsPage.js (A wrapper to include Navbar and Footer for a standalone view)

import React from 'react';
import Navbar from "../components/Navbar"; 
import EventAndAnnouncementComponents from '../components/EventAndAnnouncementComponents';
import Footer from '../components/Footer';


const EventsAndAnnouncements = () => {
    const user = null; // Replace with actual user context or props
    const logout = () => {}; // Replace with actual logout function
    return (
        <div className="min-h-screen bg-gray-50 flex flex-col">
            
            {/* 1. Header (Navbar) - Using the exact component from your input */}
            <Navbar user={user} logout={logout} />
            
            {/* 2. Main Content Area */}
            <main className="flex-grow w-full">
                {/* The actual event and announcement content */}
                <EventAndAnnouncementComponents /> 
            </main>
            
            {/* 3. Footer */}
            <Footer />
            
        </div>
    );
};

export default EventsAndAnnouncements;


// ----------------------------------------------------------------------
// NOTE: The inner component (EventsAndAnnouncements.js) remains clean:
// (src/components/EventsAndAnnouncements.js)
// ----------------------------------------------------------------------

/*
// src/components/EventsAndAnnouncements.js (Content ONLY, NO NAVBAR IMPORT)
import React from 'react';
// ... (All event, announcement, card, and pagination logic goes here) ...

const EventsAndAnnouncements = () => {
    // ... (logic) ...
    return (
        <section className="py-16 bg-gray-50">
            // ... (Event and Announcement Layout) ...
        </section>
    );
};

export default EventsAndAnnouncements;
*/

// Note: I renamed the original content component to EventsAndAnnouncementsContent 
// and wrapped it in the new page component to reflect the requested layout structure 
// while keeping the content component reusable.