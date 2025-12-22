import React from 'react';
import { Users, Calendar, MessageSquare } from 'lucide-react'; // Assuming you have these icons

export default function QuickAccessCard() {
  return (
    <div className="bg-indigo-900 p-6 rounded-xl shadow-lg min-h-[150px]">
      <h2 className="text-xl font-bold text-white mb-4">Quick Access</h2>
      <nav className="space-y-3">
        
        <a href="/alumni" className="flex items-center gap-3 text-white/90 hover:text-white transition group">
          <Users className="w-5 h-5 group-hover:text-indigo-300" />
          Alumni Directory
        </a>
        
        <a href="/events" className="flex items-center gap-3 text-white/90 hover:text-white transition group">
          <Calendar className="w-5 h-5 group-hover:text-indigo-300" />
          Upcoming Events
        </a>
        
        <a href="/messages" className="flex items-center gap-3 text-white/90 hover:text-white transition group">
          <MessageSquare className="w-5 h-5 group-hover:text-indigo-300" />
          Messages
        </a>

      </nav>
    </div>
  );
}