import React from 'react'
import { Input } from './ui/input'
import { Button } from './ui/button'

const FilterSidebar = ({products, search, setSearch, category, setCategory, brand, setBrand, priceRange, setPriceRange}) => {
  const Categories = products.map(p=> p.category)
  const uniqueCategories = ["All",...new Set(Categories)]
  const Brands = products.map(p=> p.brand)
  const uniqueBrands = ["All",...new Set(Brands)]
  return (
    <div className="bg-gray-100 mt-10 p-4 rounded-md h-max hidden md:block w-64">
      {/* Search */}
      <Input 
        type="text" 
        placeholder="Search products..." 
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="bg-white p-2 rounded-md border-gray-400 border-2 w-full"/>
      {/* Categories */}
      <h1 className="mt-5 font-semibold text-xl">Category</h1>
      <div className="flex flex-col gap-2 mt-3">
        {
          uniqueCategories.map((cat,index)=>{
            return<div key={index} className='flex items-center gap-2'>
              <input 
                type="radio"
                name="category"
                checked={category === cat}
                onChange={() => setCategory(cat)}
              />
              <label>{cat}</label>
            </div>
          })
        }
      </div>
      {/* Brands */}
      <h1 className="mt-5 font-semibold text-xl">Brand</h1>
      <select 
        value={brand}
        onChange={(e) => setBrand(e.target.value)}
        className='bg-white w-full p-2 border-gray-200 border-2 rounded-md'>
        {
          uniqueBrands.map((item,index)=>{
            return <option key={index} value={item}>{item.toUpperCase()}</option>
          })
        }
      </select>
      {/* price range */}
      <h1 className='mt-5 font-semibold text-xl mb-3'>Price Range</h1>
      <div className="flex flex-col gap-2">
        <label>
          Price Range: ₹{priceRange[0]} - ₹{priceRange[1]}
        </label>
        <input 
          type="range" 
          min="0" 
          max="999999" 
          step="100" 
          value={priceRange[0]}
          onChange={(e) => setPriceRange([parseInt(e.target.value), priceRange[1]])}
          className="w-full"
        />
        <input 
          type="range" 
          min="0" 
          max="999999" 
          step="100" 
          value={priceRange[1]}
          onChange={(e) => setPriceRange([priceRange[0], parseInt(e.target.value)])}
          className="w-full"
        />
      </div>
      {/* Reset button */}
      <Button 
        onClick={() => {
          setSearch("")
          setCategory("All")
          setBrand("All")
          setPriceRange([0, 999999])
        }}
        className="bg-blue-600 text-white mt-5 cursor-pointer w-full">
        Reset Filters
      </Button>
    </div>
  )
}

export default FilterSidebar
