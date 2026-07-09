import React from 'react'
import { Button } from './ui/button'
import { ShoppingCart } from 'lucide-react'
import { Skeleton } from './ui/skeleton'


const ProductCard = ({ product,loading }) => {

  const{productImg,productPrice,productName}=product
  return (
    <div className='shadow-lg rounded-lg overflow-hidden h-max transition-transform duration-300 hover:scale-110'>
      <div className='w-full h-full aspect-square overflow-hidden'>
        {
          loading ? <Skeleton className="w-full h-full rounded-lg"/> : <img src={productImg[0]?.url} alt="" className="w-full h-full transition-transform duration-300 hover:scale-110"/>
        }
        

      </div>
      <div className='px-2 space-y-1'>
        <h1 className='h-12 font-semibold line-clamp-2'>{productName}</h1>
        <h2 className='semi-bold'>₹{productPrice}</h2>
        <Button className='bg-blue-500 hover:bg-blue-600 text-white mb-3 w-full'><ShoppingCart/>Add to Cart</Button>
      </div>
      
    </div>
  )
}

export default ProductCard
