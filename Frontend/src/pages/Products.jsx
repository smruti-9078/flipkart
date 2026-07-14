import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { useDispatch } from "react-redux";

import FilterSidebar from "@/components/FilterSidebar";
import ProductCard from "@/components/ProductCard";

import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { setProducts } from "@/redux/productsSlice";

const Products = () => {
  const [allProducts, setAllProducts] = useState([]);
  const [loading, setLoading] = useState(false);

  // Filters
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [brand, setBrand] = useState("All");
  const [priceRange, setPriceRange] = useState([0, 999999]);

  // Sorting
  const [sortOrder, setSortOrder] = useState("");

  const dispatch = useDispatch();

  useEffect(() => {
    const getAllProducts = async () => {
      try {
        setLoading(true);

        const response = await axios.get(
          "http://localhost:8000/api/product/all-products"
        );
        console.log(response.data);

        if (response.data.success) {
          setAllProducts(response.data.products);
          dispatch(setProducts(response.data.products));
          console.log("Products loaded:", response.data.products);
        }
      } catch (error) {
        console.log(error);

        toast.error(
          error.response?.data?.message || "Failed to fetch products"
        );
      } finally {
        setLoading(false);
      }
    };

    getAllProducts();
  }, [dispatch]);

  // Filter + Sort
  const filteredAndSortedProducts = useMemo(() => {
    let filtered = [...allProducts];
    console.log("Starting filter with", filtered.length, "products");

    // Search
    if (search.trim() !== "") {
      filtered = filtered.filter((item) => {
        const productName = item.productName || item.name || item.title || "";
        return productName.toLowerCase().includes(search.toLowerCase());
      });
    }

    // Category
    if (category !== "All") {
      filtered = filtered.filter(
        (item) =>
          item.category?.toLowerCase() ===
          category.toLowerCase()
      );
    }

    // Brand
    if (brand !== "All") {
      filtered = filtered.filter(
        (item) =>
          item.brand?.toLowerCase() ===
          brand.toLowerCase()
      );
    }

    // Price Range
    filtered = filtered.filter(
      (item) =>
        item.productPrice >= priceRange[0] &&
        item.productPrice <= priceRange[1]
    );

    // Sorting
    if (sortOrder === "low-to-high") {
      filtered.sort((a, b) => a.productPrice - b.productPrice);
    }

    if (sortOrder === "high-to-low") {
      filtered.sort((a, b) => b.productPrice - a.productPrice);
    }

    console.log("Filtered products:", filtered.length);
    return filtered;
  }, [
    allProducts,
    search,
    category,
    brand,
    priceRange,
    sortOrder,
  ]);

  return (
    <div className="pt-20 pb-10">
      <div className="max-w-7xl mx-auto flex gap-7">
        {/* Sidebar */}
        <FilterSidebar
          products={allProducts}
          search={search}
          setSearch={setSearch}
          category={category}
          setCategory={setCategory}
          brand={brand}
          setBrand={setBrand}
          priceRange={priceRange}
          setPriceRange={setPriceRange}
        />

        {/* Products */}
        <div className="flex-1 flex flex-col">
          {/* Sort */}
          <div className="flex justify-end mb-6">
            <Select value={sortOrder} onValueChange={setSortOrder}>
              <SelectTrigger className="w-[220px]">
                <SelectValue placeholder="Sort By Price" />
              </SelectTrigger>

              <SelectContent>
                <SelectGroup>
                  <SelectItem value="low-to-high">
                    Price: Low to High
                  </SelectItem>

                  <SelectItem value="high-to-low">
                    Price: High to Low
                  </SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          {/* Loading */}
          {loading && (
            <div className="flex justify-center items-center h-64">
              <h2 className="text-lg font-semibold">
                Loading Products...
              </h2>
            </div>
          )}

          {/* No Products */}
          {!loading && filteredAndSortedProducts.length === 0 && (
            <div className="flex justify-center items-center h-64">
              <h2 className="text-xl font-semibold text-gray-500">
                No Products Found
              </h2>
            </div>
          )}

          {/* Product Grid */}
          {!loading && filteredAndSortedProducts.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-6">
              {filteredAndSortedProducts.map((product) => (
                <ProductCard
                  key={product._id}
                  product={product}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Products;