import React, { useEffect, useState } from "react";
import { UploadCloud, X } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import { useSelector } from "react-redux";
import axios from "axios";
import { toast } from "sonner";

const EditProduct = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const { products } = useSelector((store) => store.product);

  const product = products.find((item) => item._id === id);

  const accessToken = localStorage.getItem("accessToken");

  const [formData, setFormData] = useState({
    productName: "",
    productDescription: "",
    productPrice: "",
    category: "",
    brand: "",
  });

  const [existingImages, setExistingImages] = useState([]);
  const [newImages, setNewImages] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (product) {
      setFormData({
        productName: product.productName,
        productDescription: product.productDescription,
        productPrice: product.productPrice,
        category: product.category,
        brand: product.brand,
      });

      setExistingImages(product.productImg || []);
    }
  }, [product]);

  const handleChange = (e) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  const handleImageChange = (e) => {
    const files = Array.from(e.target.files);

    setNewImages((prev) => [...prev, ...files]);

    e.target.value = "";
  };

  const removeExistingImage = (index) => {
    setExistingImages((prev) =>
      prev.filter((_, i) => i !== index)
    );
  };

  const removeNewImage = (index) => {
    setNewImages((prev) =>
      prev.filter((_, i) => i !== index)
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);

      const payload = new FormData();

      Object.entries(formData).forEach(([key, value]) => {
        payload.append(key, value);
      });

      payload.append(
        "existingImages",
        JSON.stringify(existingImages)
      );

      newImages.forEach((img) => {
        payload.append("productImg", img);
      });

      const res = await axios.put(
        `http://localhost:8000/api/product/update/${id}`,
        payload,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "multipart/form-data",
          },
        }
      );

      if (res.data.success) {
        toast.success("Product Updated");
        navigate("/dashboard/products");
      }
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Update failed"
      );
    } finally {
      setLoading(false);
    }
  };

  if (!product) {
    return (
      <div className="text-center mt-20 text-2xl">
        Product Not Found
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-100 p-8">

      <div className="max-w-6xl mx-auto bg-white rounded-xl shadow-lg p-8">

        <h1 className="text-3xl font-bold mb-8">
          Edit Product
        </h1>

        <form
          onSubmit={handleSubmit}
          className="space-y-6"
        >

          <input
            className="w-full border p-3 rounded-lg"
            name="productName"
            value={formData.productName}
            onChange={handleChange}
            placeholder="Product Name"
          />

          <textarea
            rows="5"
            className="w-full border p-3 rounded-lg"
            name="productDescription"
            value={formData.productDescription}
            onChange={handleChange}
          />

          <div className="grid md:grid-cols-3 gap-5">

            <input
              type="number"
              className="border p-3 rounded-lg"
              name="productPrice"
              value={formData.productPrice}
              onChange={handleChange}
            />

            <input
              className="border p-3 rounded-lg"
              name="brand"
              value={formData.brand}
              onChange={handleChange}
            />

            <select
              className="border p-3 rounded-lg"
              name="category"
              value={formData.category}
              onChange={handleChange}
            >
              <option>Electronics</option>
              <option>Fashion</option>
              <option>Furniture</option>
              <option>Beauty</option>
              <option>Mobile</option>
            </select>

          </div>

          <h2 className="font-semibold">
            Existing Images
          </h2>

          <div className="grid grid-cols-5 gap-4">

            {existingImages.map((img, index) => (
              <div
                key={index}
                className="relative"
              >

                <img
                  src={img.url}
                  alt=""
                  className="h-28 w-full rounded-lg object-cover border"
                />

                <button
                  type="button"
                  onClick={() =>
                    removeExistingImage(index)
                  }
                  className="absolute top-2 right-2 bg-red-500 text-white rounded-full p-1"
                >
                  <X size={15} />
                </button>

              </div>
            ))}

          </div>

          <label className="border-2 border-dashed rounded-xl h-48 flex justify-center items-center flex-col cursor-pointer">

            <UploadCloud size={40} />

            <p>Add New Images</p>

            <input
              hidden
              multiple
              type="file"
              onChange={handleImageChange}
            />

          </label>

          {newImages.length > 0 && (
            <div className="grid grid-cols-5 gap-4">

              {newImages.map((img, index) => (
                <div
                  key={index}
                  className="relative"
                >

                  <img
                    src={URL.createObjectURL(img)}
                    alt=""
                    className="h-28 rounded-lg object-cover"
                  />

                  <button
                    type="button"
                    onClick={() =>
                      removeNewImage(index)
                    }
                    className="absolute top-2 right-2 bg-red-500 text-white rounded-full p-1"
                  >
                    <X size={15} />
                  </button>

                </div>
              ))}

            </div>
          )}

          <button
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700"
          >
            {loading ? "Updating..." : "Update Product"}
          </button>

        </form>

      </div>

    </div>
  );
};

export default EditProduct;