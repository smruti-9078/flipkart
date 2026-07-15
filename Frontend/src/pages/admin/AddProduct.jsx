import React, { useState} from 'react'
import { UploadCloud } from "lucide-react";

const AddProduct = () => {
    const [formData, setFormData] = useState({
    productName: "",
    productDescription: "",
    productPrice: "",
    category: "",
    brand: "",
    stock: "",
  });

  const [images, setImages] = useState([]);

  const handleChange = (e) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  const handleImageChange = (e) => {
    const files = Array.from(e.target.files);
    setImages(files);
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    console.log(formData);
    console.log(images);
  }

  return (
    <div className="min-h-screen bg-slate-100 py-20 pr-20 mx-auto px-4">
      <div className="max-w-5xl mx-auto bg-white rounded-xl shadow-lg p-8">
        <h1 className="text-3xl font-bold text-gray-800 mb-8">
          Add New Product
        </h1>

        <form onSubmit={handleSubmit} className="space-y-6">

          {/* Product Name */}
          <div>
            <label className="block font-medium mb-2">
              Product Name
            </label>

            <input
              type="text"
              name="productName"
              value={formData.productName}
              onChange={handleChange}
              placeholder="Enter Product Name"
              className="w-full border rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block font-medium mb-2">
              Product Description
            </label>

            <textarea
              rows={5}
              name="productDescription"
              value={formData.productDescription}
              onChange={handleChange}
              placeholder="Write product description..."
              className="w-full border rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="grid md:grid-cols-2 gap-6">

            {/* Price */}
            <div>
              <label className="block font-medium mb-2">
                Price
              </label>

              <input
                type="number"
                name="productPrice"
                value={formData.productPrice}
                onChange={handleChange}
                placeholder="₹ 999"
                className="w-full border rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Stock */}
            <div>
              <label className="block font-medium mb-2">
                Stock
              </label>

              <input
                type="number"
                name="stock"
                value={formData.stock}
                onChange={handleChange}
                placeholder="50"
                className="w-full border rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Category */}
            <div>
              <label className="block font-medium mb-2">
                Category
              </label>

              <select
                name="category"
                value={formData.category}
                onChange={handleChange}
                className="w-full border rounded-lg p-3"
              >
                <option value="">Select Category</option>
                <option>Electronics</option>
                <option>Fashion</option>
                <option>Furniture</option>
                <option>Shoes</option>
                <option>Beauty</option>
              </select>
            </div>

            {/* Brand */}
            <div>
              <label className="block font-medium mb-2">
                Brand
              </label>

              <input
                type="text"
                name="brand"
                value={formData.brand}
                onChange={handleChange}
                placeholder="Apple"
                className="w-full border rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          {/* Upload Images */}
          <div>
            <label className="block font-medium mb-3">
              Product Images
            </label>

            <label className="border-2 border-dashed rounded-xl h-52 flex flex-col justify-center items-center cursor-pointer hover:border-blue-500 transition">

              <UploadCloud size={45} className="text-blue-600" />

              <p className="mt-3 text-gray-600">
                Click to upload images
              </p>

              <input
                type="file"
                multiple
                hidden
                onChange={handleImageChange}
              />
            </label>

            {/* Preview */}
            {images.length > 0 && (
              <div className="grid grid-cols-5 gap-4 mt-5">
                {images.map((img, index) => (
                  <img
                    key={index}
                    src={URL.createObjectURL(img)}
                    alt=""
                    className="h-28 w-full object-cover rounded-lg border"
                  />
                ))}
              </div>
            )}
          </div>

          {/* Submit */}
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition"
          >
            Add Product
          </button>
        </form>
      </div>
    </div>
  )
}

export default AddProduct