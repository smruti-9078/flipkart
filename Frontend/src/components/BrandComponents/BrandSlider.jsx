import React from "react";
import "./BrandSlider.css";

const brands = [
  "/brands/nike-logo.png",
  "/brands/adidas.png",
  "/brands/apple-logo.png",
  "/brands/png-clipart-puma-icons-7.png",
  "/brands/samsung_logo.png",
  "/brands/boat-logo.png",
];

const BrandSlider = () => {
  return (
    <div className="brand-slider">
      <div className="brand-track">
        {brands.concat(brands).map((brand, index) => (
          <div className="brand-item" key={index}>
            <img src={brand} alt="brand" />
          </div>
        ))}
      </div>
    </div>
  );
};

export default BrandSlider;