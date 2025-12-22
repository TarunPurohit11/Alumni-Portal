import React, { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar"; // <-- import your Navbar
import Footer from "../components/Footer"; // optional if you have Footer

const AlumniCard = ({ alumnus, onClick }) => {
  const initials = alumnus.name
    .split(" ")
    .map(n => n[0])
    .join("");

  return (
    <div
      onClick={onClick}
      className="cursor-pointer bg-white rounded-xl shadow-lg p-5 flex flex-col items-center text-center border-t-4 border-indigo-600 hover:shadow-xl transition duration-300"
    >
      <div className="w-20 h-20 bg-indigo-100 rounded-full overflow-hidden mb-3 flex items-center justify-center text-indigo-700 text-xl font-bold">
        {alumnus.avatarUrl ? (
          <img
            src={alumnus.avatarUrl}
            alt={alumnus.name}
            className="w-full h-full object-cover"
          />
        ) : (
          initials
        )}
      </div>
      <h3 className="text-xl font-bold text-gray-900">{alumnus.name}</h3>
      <p className="text-sm text-indigo-600 font-medium mb-1">{alumnus.title}</p>
      <p className="text-sm text-gray-500 mb-3">
        {alumnus.company}
        {alumnus.graduationYear && ` • ${alumnus.graduationYear}`}
      </p>
      <button className="w-full mt-auto text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 px-4 py-2 rounded-lg transition duration-150">
        View Profile
      </button>
    </div>
  );
};

const FilterSection = ({ title, options, filterType, handleFilterChange, selectedFilters }) => (
  <div className="mb-6 pb-4 border-b border-gray-200">
    <h4 className="text-lg font-semibold text-gray-800 mb-3">{title}</h4>
    <div className="space-y-2 max-h-40 overflow-y-auto pr-2 custom-scrollbar">
      {options.map(option => (
        <label key={option} className="flex items-center text-sm text-gray-600 hover:text-indigo-600 transition duration-150">
          <input 
            type="checkbox" 
            value={option}
            checked={selectedFilters[filterType].includes(option)}
            onChange={() => handleFilterChange(filterType, option)}
            className="form-checkbox h-4 w-4 text-indigo-600 rounded border-gray-300"
          />
          <span className="ml-2">{option}</span>
        </label>
      ))}
    </div>
  </div>
);

const AlumniDirectory = ({ user, logout }) => {
  const [alumni, setAlumni] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedFilters, setSelectedFilters] = useState({
    expertise: [],
    year: [],
    company: [],
  });
  const [currentPage, setCurrentPage] = useState(1);

  const navigate = useNavigate();
  const itemsPerPage = 9;

  useEffect(() => {
    const fetchAlumni = async () => {
      try {
        const res = await axios.get("http://localhost:8080/api/alumni/public");
        if (res.data && Array.isArray(res.data.content)) {
            console.log("Fetched alumni:", res.data.content);

          setAlumni(res.data.content);
        } else {
          setAlumni([]);
        }
      } catch (err) {
        console.error("Failed to fetch alumni", err);
        setAlumni([]);
      } finally {
        setLoading(false);
      }
    };
    fetchAlumni();
  }, []);

  const handleFilterChange = (filterType, value) => {
    setSelectedFilters(prev => {
      const currentList = prev[filterType];
      if (currentList.includes(value)) {
        return { ...prev, [filterType]: currentList.filter(item => item !== value) };
      } else {
        return { ...prev, [filterType]: [...currentList, value] };
      }
    });
    setCurrentPage(1);
  };

  const filteredAlumni = alumni.filter(a => {
    const matchesSearch = `${a.name} ${a.company} ${a.title}`.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesExpertise =
      selectedFilters.expertise.length === 0 ||
      selectedFilters.expertise.some(tag => a.expertise?.includes(tag));
    const matchesCompany =
      selectedFilters.company.length === 0 || selectedFilters.company.includes(a.company);
    const matchesYear =
      selectedFilters.year.length === 0 || selectedFilters.year.includes(a.graduationYear);
    return matchesSearch && matchesExpertise && matchesCompany && matchesYear;
  });

  const totalPages = Math.ceil(filteredAlumni.length / itemsPerPage);
  const paginatedAlumni = filteredAlumni.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const handlePageChange = (page) => {
    if (page >= 1 && page <= totalPages) setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const mockFilterOptions = {
    expertise: ["AI/ML", "Web Dev", "Cyber Security", "Cloud", "Data", "UX/UI"],
    year: [2021, 2018, 2015, 2012, 2005],
    company: ["Google", "Microsoft", "TCS", "Flipkart", "Tesla"],
  };

  return (
    <div>
      {/* 1. Navbar */}
      <Navbar user={user} logout={logout} />

      {/* 2. Main Section */}
      <section className="py-12 bg-gray-50 min-h-screen">
        <div className="max-w-7xl mx-auto px-4">
          {/* Header */}
          <div className="text-center mb-10 bg-white p-6 rounded-xl shadow-md border-t-4 border-indigo-600">
            <h1 className="text-4xl font-extrabold text-gray-900">Alumni Directory</h1>
            <p className="mt-2 text-lg text-gray-600">Connect with our alumni across the globe</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Sidebar */}
            <aside className="lg:col-span-1 bg-white p-6 rounded-xl shadow-lg h-fit sticky top-8">
              <h2 className="text-2xl font-bold text-indigo-700 mb-4 pb-2 border-b border-indigo-100">
                Find Alumni
              </h2>
              <div className="mb-6">
                <input
                  type="text"
                  placeholder="Search by name, company, or title..."
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  className="w-full p-2 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
              <FilterSection
                title="Expertise"
                options={mockFilterOptions.expertise}
                filterType="expertise"
                handleFilterChange={handleFilterChange}
                selectedFilters={selectedFilters}
              />
              <FilterSection
                title="Graduation Year"
                options={mockFilterOptions.year}
                filterType="year"
                handleFilterChange={handleFilterChange}
                selectedFilters={selectedFilters}
              />
              <FilterSection
                title="Current Company"
                options={mockFilterOptions.company}
                filterType="company"
                handleFilterChange={handleFilterChange}
                selectedFilters={selectedFilters}
              />
            </aside>

            {/* Alumni Grid */}
            <div className="lg:col-span-3">
              {loading ? (
                <div className="text-center text-gray-600">Loading alumni...</div>
              ) : paginatedAlumni.length === 0 ? (
                <div className="text-center text-gray-600">No alumni found.</div>
              ) : (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {paginatedAlumni.map(alumnus => (
                      <AlumniCard
                        key={alumnus.id}
                        alumnus={alumnus}
                        onClick={() => navigate(`/profile/${alumnus.id}`)}
                      />
                    ))}
                  </div>

                  <div className="mt-10 flex justify-center items-center space-x-2">
                    <button
                      onClick={() => handlePageChange(currentPage - 1)}
                      disabled={currentPage === 1}
                      className={`px-4 py-2 text-sm font-medium rounded-l-lg transition duration-150 border-r 
                        ${currentPage === 1 ? "bg-gray-200 text-gray-500" : "bg-indigo-500 text-white hover:bg-indigo-600"}`}
                    >
                      &larr; Previous
                    </button>
                    <span className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border-t border-b">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => handlePageChange(currentPage + 1)}
                      disabled={currentPage === totalPages}
                      className={`px-4 py-2 text-sm font-medium rounded-r-lg transition duration-150 border-l
                        ${currentPage === totalPages ? "bg-gray-200 text-gray-500" : "bg-indigo-500 text-white hover:bg-indigo-600"}`}
                    >
                      Next &rarr;
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </section>
       {/* 3. Footer */}
            <Footer />
    </div>
  );
};

export default AlumniDirectory;
