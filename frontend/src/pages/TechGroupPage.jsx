// src/pages/TechGroupPage.jsx
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import axios from "axios";
import { useAuth } from "../context/AuthContext";

const api = axios.create({ baseURL: "http://localhost:8080" });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function TechGroupPage() {
  const { user, logout } = useAuth();
  const { groupId } = useParams();

  const [group, setGroup] = useState(null);
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newPostTitle, setNewPostTitle] = useState("");
  const [newPostContent, setNewPostContent] = useState("");

  const fetchGroupData = async () => {
    try {
      const groupRes = await api.get(`/api/groups/${groupId}`);
      setGroup(groupRes.data);
      const postsRes = await api.get(`/api/groups/${groupId}/posts`);
      setPosts(postsRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGroupData();
  }, [groupId]);

  const handleAddPost = async () => {
    if (!newPostTitle.trim() || !newPostContent.trim()) return;
    try {
      await api.post(`/api/groups/${groupId}/posts`, {
        title: newPostTitle,
        content: newPostContent,
      });
      setNewPostTitle("");
      setNewPostContent("");
      fetchGroupData();
    } catch (err) {
      alert("Failed to create post");
    }
  };

  const handleDeletePost = async (postId) => {
    if (!window.confirm("Delete this post?")) return;
    await api.delete(`/api/groups/posts/${postId}`);
    fetchGroupData();
  };

  if (loading) return <div className="text-center py-20 animate-pulse text-gray-500">Loading community...</div>;
  if (!group) return <div className="text-center py-20">Group not found</div>;

  const students = group.members?.filter(m => m.role === "STUDENT") || [];
  const alumni = group.members?.filter(m => m.role === "ALUMNI") || [];

  return (
    <div className="flex flex-col min-h-screen bg-[#F3F4F6]">
      <Navbar user={user} logout={logout} />

      {/* Header Banner */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 py-8">
          <h1 className="text-3xl font-bold text-gray-900">{group.title}</h1>
          <p className="text-gray-600 mt-2 max-w-2xl">{group.description}</p>
        </div>
      </div>

      <div className="flex-1 max-w-7xl mx-auto w-full px-4 py-8 grid grid-cols-12 gap-8">
        
        {/* LEFT COLUMN – STUDENTS */}
        <aside className="hidden lg:block col-span-3 space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="bg-indigo-50 px-4 py-3 border-b border-gray-100">
              <h4 className="font-bold text-indigo-900 flex items-center gap-2">
                <span>🎓</span> Students
                <span className="ml-auto text-xs bg-indigo-200 px-2 py-0.5 rounded-full">{students.length}</span>
              </h4>
            </div>
            <div className="p-2 divide-y divide-gray-50">
              {students.map(s => (
                <div key={s.id} className="p-3 hover:bg-gray-50 transition-colors rounded-lg group">
                  <p className="text-sm font-medium text-gray-700">{s.name}</p>
                  <p className="text-[10px] uppercase tracking-wider text-gray-400">Current Student</p>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* CENTER COLUMN – POSTS */}
        <main className="col-span-12 lg:col-span-6 space-y-6">
          {/* CREATE POST CARD */}
          {(user?.role === "ADMIN" || user?.role === "ALUMNI") && (
            <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
              <h3 className="text-sm font-semibold text-gray-500 mb-3 uppercase tracking-tight">Share an update</h3>
              <input
                className="w-full px-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none mb-3 transition-all"
                placeholder="Catchy title..."
                value={newPostTitle}
                onChange={(e) => setNewPostTitle(e.target.value)}
              />
              <textarea
                className="w-full px-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none mb-3 transition-all min-h-[100px]"
                placeholder="What's on your mind?"
                value={newPostContent}
                onChange={(e) => setNewPostContent(e.target.value)}
              />
              <div className="flex justify-end">
                <button
                  onClick={handleAddPost}
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-lg font-medium transition-colors shadow-sm"
                >
                  Post to Group
                </button>
              </div>
            </div>
          )}

          {/* POST FEED */}
          <div className="space-y-4">
            {posts.length === 0 && <p className="text-center text-gray-400 py-10">No posts yet. Start the conversation!</p>}
            {posts.map(post => {
              const canDelete = user?.role === "ADMIN" || post.ownPost;
              return (
                <div key={post.id} className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 hover:border-indigo-200 transition-colors">
                  <div className="flex justify-between items-start mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-700 font-bold">
                        {post.createdByName?.charAt(0)}
                      </div>
                      <div>
                        <h4 className="font-bold text-gray-900 leading-none">{post.title}</h4>
                        <p className="text-xs text-gray-500 mt-1">Posted by <span className="text-indigo-600 font-medium">{post.createdByName}</span></p>
                      </div>
                    </div>
                    {canDelete && (
                      <button
                        onClick={() => handleDeletePost(post.id)}
                        className="text-gray-400 hover:text-red-500 transition-colors"
                        title="Delete Post"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    )}
                  </div>
                  <p className="text-gray-700 leading-relaxed whitespace-pre-wrap">{post.content}</p>
                </div>
              );
            })}
          </div>
        </main>

        {/* RIGHT COLUMN – ALUMNI */}
        <aside className="col-span-12 lg:col-span-3 space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="bg-emerald-50 px-4 py-3 border-b border-gray-100">
              <h4 className="font-bold text-emerald-900 flex items-center gap-2">
                <span>⭐</span> Alumni Mentors
                <span className="ml-auto text-xs bg-emerald-200 px-2 py-0.5 rounded-full">{alumni.length}</span>
              </h4>
            </div>
            <div className="p-2 divide-y divide-gray-50">
              {alumni.map(a => (
                <div key={a.id} className="p-3 hover:bg-gray-50 transition-colors rounded-lg group">
                  <p className="text-sm font-semibold text-gray-700">{a.name}</p>
                  <p className="text-[10px] uppercase tracking-wider text-emerald-600 font-bold">Verified Alum</p>
                </div>
              ))}
            </div>
          </div>
          
          <div className="p-4 bg-indigo-600 rounded-xl text-white shadow-lg shadow-indigo-200">
            <h5 className="font-bold mb-1">Networking Tip</h5>
            <p className="text-xs opacity-90 text-indigo-50">Reach out to Alumni for career guidance and internship referrals!</p>
          </div>
        </aside>

      </div>

      <Footer />
    </div>
  );
}