import React, { useEffect, useState, useContext } from "react";
import { useParams } from "react-router-dom";
import { 
  MapPin, Briefcase, GraduationCap, 
  MessageCircle, ShieldCheck, Award, 
  Globe, Linkedin, Github, Mail
} from "lucide-react";
import axios from "axios";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { AuthContext } from "../context/AuthContext";

const ProfileView = () => {
  const { id } = useParams();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const { user, logout } = useContext(AuthContext);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const res = await axios.get(`http://localhost:8080/api/alumni/profile/${id}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
        });
        // profile.skills is expected to be an array from your DTO
        setProfile(res.data);
      } catch (err) {
        console.error("Failed to load profile", err);
      } finally {
        setLoading(false);
      }
    };
    if (id) fetchProfile();
  }, [id]);

  if (loading) return <ProfileSkeleton />;

  if (!profile) return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-slate-50">
      <div className="bg-white p-10 rounded-3xl shadow-sm text-center">
        <h2 className="text-2xl font-bold text-slate-800">Profile Not Found</h2>
        <p className="text-slate-500 mt-2">The user you are looking for may have moved or doesn't exist.</p>
      </div>
    </div>
  );

  const isAlumni = profile.role === "ALUMNI";

  return (
    <div className="bg-[#FBFBFE] min-h-screen font-sans antialiased">
      <Navbar user={user} logout={logout} />

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        
        {/* Profile Header Card */}
        <div className="relative bg-white rounded-[2rem] shadow-sm border border-slate-200 overflow-hidden mb-8">
          {/* Cover Image/Gradient */}
          <div className="h-48 md:h-60 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900" />
          
          <div className="px-8 pb-10">
            <div className="relative flex flex-col md:flex-row md:items-end -mt-20 md:-mt-24 gap-8">
              
              {/* Profile Picture */}
              <div className="relative group mx-auto md:mx-0">
                <div className="w-40 h-40 md:w-52 md:h-52 rounded-[2.5rem] overflow-hidden border-[6px] border-white shadow-2xl bg-slate-100 flex items-center justify-center">
                  {profile.profilePic ? (
                    <img 
                      src={profile.profilePic} 
                      alt={profile.name} 
                      className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110" 
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center bg-indigo-50">
                       <span className="text-7xl font-bold text-indigo-300 tracking-tighter">
                        {profile.name.charAt(0)}
                       </span>
                    </div>
                  )}
                </div>
                {isAlumni && (
                  <div className="absolute -bottom-2 -right-2 bg-indigo-600 text-white p-2.5 rounded-2xl border-4 border-white shadow-lg" title="Verified Alumni">
                    <ShieldCheck size={24} />
                  </div>
                )}
              </div>

              {/* Identity & Bio Summary */}
              <div className="flex-1 text-center md:text-left space-y-2">
                <div className="flex flex-col md:flex-row md:items-center gap-2 md:gap-4">
                    <h1 className="text-4xl font-black text-slate-900 tracking-tight">{profile.name}</h1>
                    <span className={`inline-block px-4 py-1 rounded-full text-[10px] font-black uppercase tracking-[0.2em] border self-center md:self-auto ${
                        isAlumni ? "bg-indigo-50 border-indigo-100 text-indigo-600" : "bg-emerald-50 border-emerald-100 text-emerald-600"
                    }`}>
                        {profile.role}
                    </span>
                </div>
                
                <div className="flex flex-wrap justify-center md:justify-start items-center gap-5 text-slate-500 font-medium">
                  {profile.title && (
                    <div className="flex items-center gap-2">
                      <Briefcase size={18} className="text-slate-400" />
                      <span className="text-lg">{profile.title} at <span className="text-slate-900">{profile.company}</span></span>
                    </div>
                  )}
                  {profile.city && (
                    <div className="flex items-center gap-2 border-l border-slate-200 pl-5">
                      <MapPin size={18} className="text-slate-400" />
                      <span>{profile.city}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Message Action */}
              <div className="mt-6 md:mt-0">
                <button className="w-full md:w-auto flex items-center justify-center gap-3 px-10 py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all shadow-xl shadow-indigo-100 active:scale-95">
                  <MessageCircle size={20} /> 
                  <span>Send Message</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Info Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Main Content (Left) */}
          <div className="lg:col-span-2 space-y-8">
            <section className="bg-white rounded-[2rem] p-8 md:p-10 border border-slate-100 shadow-sm">
              <h2 className="text-sm font-black uppercase tracking-[0.2em] text-indigo-600 mb-6">Professional Bio</h2>
              <p className="text-slate-600 leading-relaxed text-lg lg:text-xl">
                {profile.about || `${profile.name} is a valued member of our community who hasn't filled out their bio yet.`}
              </p>
            </section>

            <section className="bg-white rounded-[2rem] p-8 md:p-10 border border-slate-100 shadow-sm">
              <h2 className="text-sm font-black uppercase tracking-[0.2em] text-indigo-600 mb-8">Education History</h2>
              <div className="flex items-start gap-6 group">
                <div className="p-5 bg-indigo-50 rounded-3xl text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white transition-all duration-300">
                  <GraduationCap size={32} />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-slate-900 mb-1">{profile.course}</h3>
                  <p className="text-lg text-slate-500">Graduation Class of {profile.year}</p>
                </div>
              </div>
            </section>
          </div>

          {/* Sidebar (Right) */}
          <div className="space-y-8">
            {/* Skills Fetched and Rendered */}
            <section className="bg-white rounded-[2rem] p-8 border border-slate-100 shadow-sm">
              <div className="flex items-center gap-3 mb-6">
                <Award size={20} className="text-indigo-600" />
                <h2 className="text-sm font-black uppercase tracking-[0.2em] text-slate-900">Skills & Expertise</h2>
              </div>
              <div className="flex flex-wrap gap-2.5">
                {profile.skills && profile.skills.length > 0 ? (
                  profile.skills.map((skill, index) => (
                    <span key={index} className="px-4 py-2 bg-slate-50 border border-slate-100 text-slate-600 rounded-xl text-xs font-bold hover:border-indigo-200 hover:text-indigo-600 transition-all cursor-default">
                      {skill}
                    </span>
                  ))
                ) : (
                  <p className="text-slate-400 text-sm italic">No skills listed yet.</p>
                )}
              </div>
            </section>

            {/* Contact Info */}
            <section className="bg-white rounded-[2rem] p-8 border border-slate-100 shadow-sm">
              <h2 className="text-sm font-black uppercase tracking-[0.2em] text-slate-900 mb-6">Network</h2>
              <div className="space-y-4">
                <button className="w-full flex items-center gap-4 p-4 rounded-2xl hover:bg-indigo-50 transition-all border border-transparent hover:border-indigo-100 group text-slate-600 font-bold text-sm">
                  <Linkedin size={18} className="group-hover:text-indigo-600" />
                  <span>LinkedIn Profile</span>
                </button>
                <button className="w-full flex items-center gap-4 p-4 rounded-2xl hover:bg-indigo-50 transition-all border border-transparent hover:border-indigo-100 group text-slate-600 font-bold text-sm">
                  <Github size={18} className="group-hover:text-slate-900" />
                  <span>GitHub Repository</span>
                </button>
                <button className="w-full flex items-center gap-4 p-4 rounded-2xl hover:bg-indigo-50 transition-all border border-transparent hover:border-indigo-100 group text-slate-600 font-bold text-sm">
                  <Mail size={18} className="group-hover:text-indigo-600" />
                  <span>Email Contact</span>
                </button>
              </div>
            </section>
          </div>

        </div>
      </main>
      <Footer />
    </div>
  );
};

// Polished Shimmer Loading
const ProfileSkeleton = () => (
  <div className="max-w-6xl mx-auto px-4 py-10 animate-pulse">
    <div className="h-60 bg-slate-200 rounded-[2rem] mb-12" />
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
      <div className="lg:col-span-2 space-y-8">
        <div className="h-40 bg-slate-200 rounded-[2rem]" />
        <div className="h-60 bg-slate-200 rounded-[2rem]" />
      </div>
      <div className="h-96 bg-slate-200 rounded-[2rem]" />
    </div>
  </div>
);

export default ProfileView;