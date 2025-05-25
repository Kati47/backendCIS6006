const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const itemController = require('../controllers/itemController');

// Item validation rules
const validateItem = [
    check('name')
        .notEmpty().withMessage('Item name is required')
        .trim()
        .isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
    check('price')
        .optional()
        .isNumeric().withMessage('Price must be a number')
        .isFloat({ min: 0 }).withMessage('Price must be a positive number'),
    check('category')
        .optional()
        .isIn(['electronics', 'clothing', 'books', 'food', 'other']).withMessage('Invalid category')
];

// Routes
router.get('/', itemController.getAllItems);
router.get('/:id', itemController.getItemById);
router.post('/',  validateItem, itemController.createItem);
router.put('/:id',  validateItem, itemController.updateItem);
router.delete('/:id', itemController.deleteItem);

module.exports = router;