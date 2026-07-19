import React, { useState, useEffect } from "react";
import { UploadCloud } from "lucide-react";
import axios from "axios";
import { useDispatch, useSelector } from "react-redux";
import { setProducts } from "../../redux/productsSlice";
import { toast } from "sonner";

const AddProduct = () => {
  const accessToken = localStorage.getItem("accessToken") || "";
  const dispatch = useDispatch();
  const products = useSelector((state) => state.product?.products || []);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    productName: "",
    productDescription: "",
    productPrice: "",
    category: "",
    brand: "",
  });

  // images: array of { file: File, preview: string }
  const [images, setImages] = useState([]);

  const handleChange = (e) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  const handleImageChange = (e) => {
    const files = Array.from(e.target.files || []);

    // revoke previous previews
    images.forEach((img) => {
      if (img && img.preview) URL.revokeObjectURL(img.preview);
    });

    const next = files.map((file) => ({ file, preview: URL.createObjectURL(file) }));
    setImages(next);
  };
  const handleRemoveImage = (index) => {
  setImages((prevImages) =>
    prevImages.filter((_, i) => i !== index)
  );
};

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!accessToken) {
      toast.error("Please login first");
      return;
    }

    if (images.length === 0) {
      toast.error("Please select at least one image");
      return;
    }

    try {
      setLoading(true);
      const form = new FormData();
      form.append("productName", formData.productName);
      form.append("productDescription", formData.productDescription);
      form.append("productPrice", formData.productPrice);
      form.append("category", formData.category);
      form.append("brand", formData.brand);

      images.forEach((img) => form.append("productImg", img.file));

      const res = await axios.post(
        "http://localhost:8000/api/product/add",
        form,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "multipart/form-data",
          },
        }
      );

      if (res.data.success) {
        dispatch(setProducts([...products, res.data.product]));
        toast.success(res.data.message);

        // clear
        setFormData({
          productName: "",
          productDescription: "",
          productPrice: "",
          category: "",
          brand: "",
        });
        // revoke previews and clear
        images.forEach((img) => {
          if (img && img.preview) URL.revokeObjectURL(img.preview);
        });
        setImages([]);
      }
    } catch (error) {
      console.error(error);
      toast.error(error.response?.data?.message || "Failed to add product");
    } finally {
      setLoading(false);
    }
  };
  

  // cleanup previews on images change / unmount
  useEffect(() => {
    return () => {
      images.forEach((img) => {
        if (img && img.preview) URL.revokeObjectURL(img.preview);
      });
    };
  }, [images]);

  return (
    <div className="min-h-screen bg-slate-100 py-20 pr-20 mx-auto px-4">
      <div className="max-w-5xl mx-auto bg-white rounded-xl shadow-lg p-8">
        <h1 className="text-3xl font-bold text-gray-800 mb-8">
          Add New Product
        </h1>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Product Name */}
          <div>
            <label className="block font-medium mb-2">Product Name</label>

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
              <label className="block font-medium mb-2">Price</label>

              <input
                type="number"
                name="productPrice"
                value={formData.productPrice}
                onChange={handleChange}
                placeholder="₹ 999"
                className="w-full border rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Category */}
            <div>
              <label className="block font-medium mb-2">Category</label>

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
                <option>mobile</option>
              </select>
            </div>

            {/* Brand */}
            <div>
              <label className="block font-medium mb-2">Brand</label>

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
            <label className="block font-medium mb-3">Product Images</label>

            <label className="relative border-2 border-dashed rounded-xl h-52 flex flex-col justify-center items-center cursor-pointer hover:border-blue-500 transition">
              <UploadCloud size={45} className="text-blue-600" />

              <p className="mt-3 text-gray-600">Click to upload images</p>

              <input type="file" name="productImg" multiple hidden onChange={handleImageChange} />
            </label>

            {/* Preview */}
            {images.length > 0 && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-5">
                {images.map((imgObj, index) => (
                  <div key={index} className="relative overflow-hidden rounded-lg border">
                    <img
                      src={imgObj.preview}
                      alt={formData.productName || `preview-${index}`}
                      className="h-28 w-full object-cover"
                    />
                    <button
                      type="button"
                      onClick={() => handleRemoveImage(index)}
                      className="absolute top-2 right-2 bg-red-500 text-white rounded-full w-7 h-7 flex items-center justify-center hover:bg-red-600 transition"
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Submit */}
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition"
          >
            {loading ? "Adding Product..." : "Add Product"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default AddProduct;
