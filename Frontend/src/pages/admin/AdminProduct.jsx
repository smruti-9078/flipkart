import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Search, Trash2, SquarePen } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import axios from "axios";
import { setProducts } from "@/redux/productsSlice";


const AdminProduct = () => {
  const { products } = useSelector((store) => store.product);

  const [search, setSearch] = useState("");
  const dispatch = useDispatch()
  const accessToken =localStorage.getItem("accessToken")
  const navigate = useNavigate();
  

  const filteredProducts = products.filter(
    (product) =>
      product.productName.toLowerCase().includes(search.toLowerCase()) ||
      product.category.toLowerCase().includes(search.toLowerCase()) ||
      product.brand.toLowerCase().includes(search.toLowerCase()),
  );

  const handleDelete = async(id) => {
    try {
      const confirmDelete = window.confirm("Are you sure you want to delete this product?")
      if(!confirmDelete) return;

      const res = await axios.delete(
      `http://localhost:8000/api/product/delete/${id}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );
    if (res.data.success) {
      toast.success(res.data.message);

      dispatch(
        setProducts(
          products.filter((product) => product._id !== id)
        )
      );
    }
      
    } catch (error) {

      console.log(error);

    toast.error(
      error.response?.data?.message || "Failed to delete product"
    )
    }
  };

  const handleEdit = (id) => {
    //console.log("Edit Product:", id);
    navigate(`/dashboard/edit-product/${id}`)
     
  };

  return (
    <div className="min-h-screen bg-slate-50 p-18">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <h2 className="text-3xl font-bold text-gray-800">Products</h2>

        <div className="relative w-80">
          <Search size={20} className="absolute left-3 top-3 text-gray-400" />

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

                  <td className="p-4 font-semibold">{product.productName}</td>

                  <td className="p-4">{product.category}</td>

                  <td className="p-4">{product.brand}</td>

                  <td className="p-4 font-semibold text-blue-600">
                    ₹{product.productPrice}
                  </td>

                  <td className="p-4">
                    <div className="flex justify-between gap-3">
                      
                      <button
                        onClick={() => handleEdit(product._id)}
                        className="bg-slate-100 text-slate-600 p-2 rounded-lg hover:bg-blue-600 hover:text-white transition"
                      >
                        <SquarePen size={18} />
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
                <td colSpan={7} className="text-center py-10 text-gray-500">
                  No Products Found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AdminProduct;
