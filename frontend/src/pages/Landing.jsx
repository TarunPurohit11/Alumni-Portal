import React from "react";
import Navbar from "../components/Navbar";
import HeroSection from "../components/HeroSection";
import UpcomingEvents from "../components/UpcomingEvents";
import Footer from "../components/Footer";
import Groups from "../components/groups";
import Alumni from "../components/alumni";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <HeroSection />
      <div className="max-w-7xl mx-auto px-4">
        <UpcomingEvents />
        <Groups />
        <Alumni />
      </div>
      <Footer />
    </div>
  );
}
