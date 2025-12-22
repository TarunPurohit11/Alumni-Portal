export default function Pagination({ page, totalPages, onPageChange }) {
  return (
    <div className="flex justify-between items-center p-4 text-sm">
      <button
        disabled={page === 0}
        onClick={() => onPageChange(page - 1)}
        className="px-3 py-1 border rounded disabled:opacity-50"
      >
        Prev
      </button>
      <span>Page {page + 1} of {totalPages}</span>
      <button
        disabled={page + 1 === totalPages}
        onClick={() => onPageChange(page + 1)}
        className="px-3 py-1 border rounded disabled:opacity-50"
      >
        Next
      </button>
    </div>
  );
}
