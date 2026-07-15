import React, { useState} from 'react'
import { useSelector } from 'react-redux';
import { Search, Pencil, Trash2 } from 'lucide-react';

const AdminProduct = () => {
    const { products } = useSelector((store) => store.product);

  const [search, setSearch] = useState("");

  const filteredProducts = products.filter(
    (product) =>
      product.productName.toLowerCase().includes(search.toLowerCase()) ||
      product.category.toLowerCase().includes(search.toLowerCase()) ||
      product.brand.toLowerCase().includes(search.toLowerCase())
  );

  const handleDelete = (id) => {
    console.log("Delete Product:", id);
    // Delete API Call
  };

  const handleEdit = (id) => {
    console.log("Edit Product:", id);
    // Navigate to Edit Product Page
  };

  return (
    <div className="min-h-screen bg-slate-50 p-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <h2 className="text-3xl font-bold text-gray-800">
          Products
        </h2>

        <div className="relative w-80">
          <Search
            size={20}
            className="absolute left-3 top-3 text-gray-400"
          />

          <input
            type="text"
            placeholder="Search Product..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-3 border rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl shadow overflow-hidden">

        <table className="w-full">

          <thead className="bg-blue-600 text-white">
            <tr>
              <th className="p-4 text-left">Image</th>
              <th className="p-4 text-left">Product</th>
              <th className="p-4 text-left">Category</th>
              <th className="p-4 text-left">Brand</th>
              <th className="p-4 text-left">Price</th>
              <th className="p-4 text-left">Stock</th>
              <th className="p-4 text-center">Actions</th>
            </tr>
          </thead>

          <tbody>
            {filteredProducts.length > 0 ? (
              filteredProducts.map((product) => (
                <tr
                  key={product._id}
                  className="border-b hover:bg-slate-50 transition"
                >
                  <td className="p-4">
                    <img
                      src={product.productImg?.[0]?.url}
                      alt={product.productName}
                      className="w-16 h-16 object-cover rounded-lg border"
                    />
                  </td>

                  <td className="p-4 font-semibold">
                    {product.productName}
                  </td>

                  <td className="p-4">
                    {product.category}
                  </td>

                  <td className="p-4">
                    {product.brand}
                  </td>

                  <td className="p-4 font-semibold text-blue-600">
                    ₹{product.productPrice}
                  </td>

                  <td className="p-4">
                    {product.stock}
                  </td>

                  <td className="p-4">
                    <div className="flex justify-center gap-3">

                      <button
                        onClick={() => handleEdit(product._id)}
                        className="bg-blue-100 text-blue-600 p-2 rounded-lg hover:bg-blue-600 hover:text-white transition"
                      >
                        <Pencil size={18} />
                      </button>

                      <button
                        onClick={() => handleDelete(product._id)}
                        className="bg-red-100 text-red-600 p-2 rounded-lg hover:bg-red-600 hover:text-white transition"
                      >
                        <Trash2 size={18} />
                      </button>

                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td
                  colSpan={7}
                  className="text-center py-10 text-gray-500"
                >
                  No Products Found
                </td>
              </tr>
            )}
          </tbody>

        </table>

      </div>
    </div>
  )
}

export default AdminProduct