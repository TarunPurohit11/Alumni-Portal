export default function CareerCenter() {
  return (
    <section className="mt-16 mb-16">
      <h2 className="text-2xl font-bold text-gray-800">Career Center</h2>
      <p className="text-gray-500 mb-6">Exclusive job postings from alumni, for alumni.</p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* Job Card 1 - Professional styling with border and shadow */}
        <div className="bg-white p-6 rounded-xl shadow-lg border border-gray-200 hover:shadow-xl transition duration-300">
          
          {/* Tag: Muted and professional */}
          <span className="text-xs bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full font-medium tracking-wide">Alumni Verified</span>
          
          <h3 className="text-xl font-bold mt-3 text-gray-800">Marketing Specialist</h3>
          <p className="text-gray-500 text-sm mt-1">Remote – Deloitte</p>
          
          {/* Action button matching the theme */}
          <button className="mt-5 text-indigo-600 font-semibold hover:text-indigo-800 transition duration-150">
            Apply Now →
          </button>
        </div>

        {/* Job Card 2 - Professional styling with border and shadow */}
        <div className="bg-white p-6 rounded-xl shadow-lg border border-gray-200 hover:shadow-xl transition duration-300">
          
          {/* Tag: Muted and professional */}
          <span className="text-xs bg-gray-100 text-gray-600 px-3 py-1 rounded-full font-medium tracking-wide">Startup</span>
          
          <h3 className="text-xl font-bold mt-3 text-gray-800">Junior Software Engineer</h3>
          <p className="text-gray-500 text-sm mt-1">Seattle, WA – Qwik Tech</p>
          
          {/* Action button matching the theme */}
          <button className="mt-5 text-indigo-600 font-semibold hover:text-indigo-800 transition duration-150">
            Apply Now →
          </button>
        </div>

        {/* Mentor Card - Deep Indigo Feature Card */}
        <div className="bg-indigo-700 text-white p-6 rounded-xl shadow-2xl">
          <h3 className="text-2xl font-bold mb-2">Need Career Advice?</h3>
          <p className="text-indigo-200 mt-2 text-md">Connect with senior alumni for mentorship and guidance across various industries.</p>
          
          {/* Button: White background, deep indigo text, professional styling */}
          <button className="mt-6 bg-white text-indigo-800 px-6 py-3 rounded-lg shadow-md font-bold hover:bg-gray-100 transition duration-200">
            Find a Mentor
          </button>
        </div>

      </div>
    </section>
  );
}