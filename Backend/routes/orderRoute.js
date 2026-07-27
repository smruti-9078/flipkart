import express from 'express';
import { isAuthenticated } from '../middleware/isAuthenticated.js';
import { placeOrder, getOrders, getAllOrders, updateOrderStatus } from '../controllers/orderController.js';

const router = express.Router();

router.post('/place-order', isAuthenticated, placeOrder);
router.get('/my-orders', isAuthenticated, getOrders);

//Admin
router.get("/admin", isAuthenticated, getAllOrders);
router.put("/admin/:orderId", isAuthenticated, updateOrderStatus);


export default router;
