import React from "react";

export default function AuthModal({ isOpen, onClose, children }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-[9999]">
       <div className="bg-white rounded-2xl shadow-xl relative w-auto h-auto p-2">

        <button
          onClick={onClose}
          className="absolute top-3 right-4 text-gray-500 hover:text-gray-700 text-2xl"
        >
          ×
        </button>

        {children}
      </div>
    </div>
  );
}
