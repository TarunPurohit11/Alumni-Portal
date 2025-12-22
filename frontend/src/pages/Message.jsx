import React, { useState } from 'react';
import { Search, Send, Smile, MoreVertical, Sparkles, ChevronLeft, Bot, ShieldCheck } from 'lucide-react';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

const USERS = [
  { id: 1, name: 'Bopar Chiuw', status: 'Online', lastMsg: '0:1m 18', avatar: 'https://i.pravatar.cc/150?u=1', online: true },
  { id: 2, name: 'Alice Johnson', status: 'Offline', lastMsg: '0:3n 21', avatar: 'https://i.pravatar.cc/150?u=a2', online: false },
];

const Message = () => {
  const [selectedUser, setSelectedUser] = useState(USERS[1]);
  const [view, setView] = useState('chat'); // 'chat' or 'guide'

  // --- VIRTUAL GUIDE VIEW ---
  if (view === 'guide') {
    return (
      <div className="flex flex-col h-screen bg-slate-900 text-white antialiased">
        <Navbar />
        <main className="flex flex-1 max-w-5xl w-full mx-auto my-8 bg-slate-800/50 rounded-[2.5rem] border border-slate-700 shadow-2xl overflow-hidden flex flex-col">
          {/* Guide Header */}
          <header className="px-8 py-6 border-b border-slate-700 flex justify-between items-center bg-slate-800">
            <div className="flex items-center gap-4">
              <button 
                onClick={() => setView('chat')}
                className="p-2 hover:bg-slate-700 rounded-full transition-colors text-slate-400 hover:text-white"
              >
                <ChevronLeft size={24} />
              </button>
              <div className="w-12 h-12 bg-indigo-500 rounded-2xl flex items-center justify-center shadow-lg shadow-indigo-500/20">
                <Sparkles size={24} className="text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold tracking-tight">Virtual Guide AI</h2>
                <div className="flex items-center gap-2 text-xs text-indigo-300 font-semibold uppercase tracking-wider">
                  <span className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse"></span>
                  System Online
                </div>
              </div>
            </div>
            <div className="flex gap-3">
              <div className="hidden md:flex items-center gap-2 bg-slate-700/50 px-3 py-1.5 rounded-lg border border-slate-600">
                <ShieldCheck size={14} className="text-emerald-400" />
                <span className="text-[11px] font-bold uppercase tracking-tighter">Secure Assistant</span>
              </div>
            </div>
          </header>

          {/* Guide Chat Body */}
          <div className="flex-1 flex flex-col items-center justify-center p-8 space-y-6">
            <div className="p-5 bg-indigo-500/10 rounded-full border border-indigo-500/20 shadow-[0_0_30px_rgba(99,102,241,0.1)]">
              <Bot size={48} className="text-indigo-400" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-white">How can I assist you today?</h1>
          </div>

          {/* Guide Input Area */}
          <footer className="p-10 bg-slate-800 border-t border-slate-700">
            <div className="max-w-3xl mx-auto flex items-center gap-4 bg-slate-900 border border-slate-700 rounded-2xl p-2 px-6 shadow-2xl focus-within:ring-2 focus-within:ring-indigo-500/50 transition-all">
              <input 
                type="text" 
                placeholder="Ask the Virtual Guide anything..." 
                className="flex-1 bg-transparent border-none focus:ring-0 text-lg py-4 text-white placeholder:text-slate-500"
              />
              <button className="bg-indigo-600 hover:bg-indigo-500 text-white p-3 rounded-xl transition-all active:scale-95 shadow-lg shadow-indigo-500/20">
                <Send size={24} />
              </button>
            </div>
          </footer>
        </main>
        <Footer />
      </div>
    );
  }

  // --- STANDARD MESSAGING VIEW ---
  return (
    <div className="flex flex-col h-screen bg-slate-50 text-slate-900 antialiased">
      <Navbar />
      <main className="flex flex-1 overflow-hidden border-t border-slate-200">
        
        {/* SIDEBAR */}
        <aside className="w-80 bg-white border-r border-slate-200 flex flex-col hidden md:flex">
          <div className="p-5 border-b border-slate-100"><h2 className="font-bold text-slate-800 tracking-tight">Messages</h2></div>
          <div className="px-4 py-4">
            <div className="relative"><Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={16} /><input type="text" placeholder="Search..." className="w-full bg-slate-100/50 border-slate-200 rounded-lg py-2 pl-10 pr-4 text-sm focus:ring-1 focus:ring-indigo-500" /></div>
          </div>
          <div className="flex-1 overflow-y-auto px-2 space-y-1">
            {USERS.map((user) => (
              <div key={user.id} onClick={() => setSelectedUser(user)} className={`flex items-center gap-3 px-3 py-3 cursor-pointer rounded-xl transition-all ${selectedUser.id === user.id ? 'bg-indigo-50 border border-indigo-100 shadow-sm' : 'hover:bg-slate-50 border border-transparent'}`}>
                <div className="relative"><img src={user.avatar} className="w-10 h-10 rounded-xl" alt="" /><span className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-white ${user.online ? 'bg-green-500' : 'bg-slate-300'}`}></span></div>
                <div className="flex-1 min-w-0"><span className="font-bold text-sm block">{user.name}</span><p className="text-[10px] text-slate-400 uppercase font-bold">{user.lastMsg}</p></div>
              </div>
            ))}
          </div>
        </aside>

        {/* MESSAGING AREA */}
        <section className="flex-1 flex flex-col bg-white">
          <header className="px-6 h-16 border-b border-slate-100 flex justify-between items-center shadow-sm">
            <div className="flex flex-col"><h3 className="font-bold text-slate-900">@{selectedUser.name.replace(' ', '').toLowerCase()}</h3><span className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mt-1">Project Workspace</span></div>
            <div className="flex items-center gap-3">
              <button 
                onClick={() => setView('guide')}
                className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all shadow-lg active:scale-95"
              >
                <Sparkles size={16} className="text-indigo-400" />
                <span>Virtual Guide</span>
              </button>
              <div className="w-px h-6 bg-slate-200 mx-1"></div>
              <button className="p-2 text-slate-400 hover:bg-slate-50 rounded-lg"><MoreVertical size={20}/></button>
            </div>
          </header>

          <div className="flex-1 overflow-y-auto p-8 space-y-8 bg-[#FAFBFF]">
            <div className="flex items-start gap-4 flex-row-reverse">
              <div className="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center text-white font-bold text-[10px]">ME</div>
              <div className="bg-slate-900 text-white p-4 rounded-2xl rounded-tr-none shadow-xl max-w-xl leading-relaxed">
                Check the Virtual Guide if you need the latest project stats!
              </div>
            </div>
          </div>

          <footer className="p-6 bg-white border-t border-slate-100">
            <div className="flex items-center gap-3 bg-slate-50 border border-slate-200 rounded-2xl p-2 px-3 focus-within:bg-white transition-all">
              <button className="p-2 text-slate-400 hover:text-indigo-500"><Smile size={20} /></button>
              <input type="text" placeholder={`Message @${selectedUser.name.split(' ')[0]}...`} className="flex-1 bg-transparent border-none focus:ring-0 text-[15px] py-2" />
              <button className="bg-indigo-600 text-white px-5 py-2 rounded-xl font-bold text-sm hover:bg-indigo-700 transition-colors">Send</button>
            </div>
          </footer>
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default Message;