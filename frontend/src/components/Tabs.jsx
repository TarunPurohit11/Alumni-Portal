export default function Tabs({ items, active, onChange }) {
  return (
    <nav className="flex px-10 border-b bg-white">
      {items.map((item) => (
        <button
          key={item}
          onClick={() => onChange(item)}
          className={`mr-8 py-3 text-sm ${
            active === item
              ? "border-b-2 border-indigo-600 text-indigo-600 font-medium"
              : "text-gray-600 hover:text-indigo-500"
          }`}
        >
          {item}
        </button>
      ))}
    </nav>
  );
}
