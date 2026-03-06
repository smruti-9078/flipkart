import React from "react";
import "./Footer.css";

const Footer = () => {
  return (
    <footer className="footer">
      <div className="footer-top">

        <div className="footer-column">
          <h4>ABOUT</h4>
          <p>Contact Us</p>
          <p>About Us</p>
          <p>Careers</p>
          <p>Flipkart Stories</p>
          <p>Press</p>
        </div>

        <div className="footer-column">
          <h4>HELP</h4>
          <p>Payments</p>
          <p>Shipping</p>
          <p>Cancellation</p>
          <p>Returns</p>
          <p>FAQ</p>
        </div>

        <div className="footer-column">
          <h4>POLICY</h4>
          <p>Return Policy</p>
          <p>Terms Of Use</p>
          <p>Security</p>
          <p>Privacy</p>
          <p>Sitemap</p>
        </div>

        <div className="footer-column">
          <h4>SOCIAL</h4>
          <p>Facebook</p>
          <p>Twitter</p>
          <p>YouTube</p>
        </div>

        <div className="footer-column address">
          <h4>Mail Us:</h4>
          <p>
            Flipkart Internet Private Limited,  
            Buildings Alyssa, Begonia &  
            Clove Embassy Tech Village,  
            Outer Ring Road, Bengaluru,  
            Karnataka, India
          </p>
        </div>

      </div>

      <div className="footer-bottom">
        <p>© 2026 YourStore.com</p>
      </div>
    </footer>
  );
};

export default Footer;