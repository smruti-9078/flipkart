import React from 'react'
import Hero from '../components/Hero.jsx'
import Features from '@/components/Features.jsx'
import BrandSlider from '@/components/BrandComponents/BrandSlider.jsx'
import Footer from '@/components/Footer/Footer.jsx'


const Home = () => {
  return (
    <div>
      <Hero/>
      <Features/>
      <h2>Our Brands</h2>
      <BrandSlider/>
      
      
    </div>
  )
}

export default Home
