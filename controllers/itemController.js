const { validationResult } = require('express-validator');
const { Item } = require('../models/item');

/**
 * Create a new item
 */
exports.createItem = async function (req, res) {
    console.log('createItem function called with body:', req.body);
    
    // Check if there are validation errors
    console.log('Running validation...');
    const errors = validationResult(req);
    console.log('Validation result:', errors);
    
    if (!errors.isEmpty()) {
        console.log('Validation errors detected:', errors.array());
        return res.status(400).json({ errors: errors.array().map(error => {
            console.log('Mapping error:', error);
            return {
                field: error.path,
                message: error.msg,
            };
        })});
    }
    console.log('Validation passed, continuing with item creation');

    try {
        // Extract data from request
        const { userId,name, description, price, category, tags } = req.body;
        
        // Create a new item instance
        console.log('Creating item instance with data...');
        const item = new Item({
            name,
            description,
            price: price || 0,
            category: category || 'other',
            tags: tags || [],
            createdBy: userId, 
            isActive: true
        });
        
        // Save the item
        console.log('Saving item to database...');
        const savedItem = await item.save();
        
        console.log('Item created successfully with ID:', savedItem._id);
        
        // Return the created item
        return res.status(201).json({
            success: true,
            data: savedItem
        });
    } catch (error) {
        console.error('Error during item creation:', error);
        return res.status(500).json({ 
            success: false,
            message: error.message 
        });
    }
};

/**
 * Get all items with optional filtering
 */
exports.getAllItems = async function (req, res) {
    console.log('getAllItems function called with query:', req.query);
    
    try {
        // Build query filters
        const filter = {};
        
        if (req.query.category) {
            filter.category = req.query.category;
        }
        
        if (req.query.isActive) {
            filter.isActive = req.query.isActive === 'true';
        }
        
        // If search term provided, search in name and description
        if (req.query.search) {
            filter.$or = [
                { name: { $regex: req.query.search, $options: 'i' } },
                { description: { $regex: req.query.search, $options: 'i' } }
            ];
        }
        
        // Parse pagination parameters
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        
        console.log('Fetching items with filter:', filter);
        
        // Get total count for pagination
        const totalItems = await Item.countDocuments(filter);
        
        // Get items with pagination
        const items = await Item.find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .select('-__v');
        
        console.log(`Found ${items.length} items`);
        
        // Return paginated results
        return res.status(200).json({
            success: true,
            count: totalItems,
            pages: Math.ceil(totalItems / limit),
            currentPage: page,
            data: items
        });
    } catch (error) {
        console.error('Error in getAllItems:', error);
        return res.status(500).json({ 
            success: false,
            message: error.message 
        });
    }
};

/**
 * Get a single item by ID
 */
exports.getItemById = async function (req, res) {
    console.log('getItemById function called with ID:', req.params.id);
    
    try {
        const item = await Item.findById(req.params.id);
        
        if (!item) {
            console.log('Item not found');
            return res.status(404).json({
                success: false,
                message: 'Item not found'
            });
        }
        
        console.log('Item found:', item._id);
        
        return res.status(200).json({
            success: true,
            data: item
        });
    } catch (error) {
        console.error('Error in getItemById:', error);
        return res.status(500).json({ 
            success: false,
            message: error.message 
        });
    }
};

/**
 * Update an item
 */
exports.updateItem = async function (req, res) {
    console.log('updateItem function called with ID:', req.params.id);
    console.log('Update data:', req.body);
    
    // Check if there are validation errors
    console.log('Running validation...');
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        console.log('Validation errors detected:', errors.array());
        return res.status(400).json({ 
            success: false,
            errors: errors.array().map(error => ({
                field: error.path,
                message: error.msg,
            }))
        });
    }
    
    try {
        // Find the item first
        const item = await Item.findById(req.params.id);
        
        if (!item) {
            console.log('Item not found');
            return res.status(404).json({
                success: false,
                message: 'Item not found'
            });
        }
        
        // Check if user has permission to update this item
        if (item.createdBy.toString() !== req.user.id && !req.user.isAdmin) {
            console.log('User not authorized to update this item');
            return res.status(403).json({
                success: false,
                message: 'Not authorized to update this item'
            });
        }
        
        // Extract data for update
        const { name, description, price, category, tags, isActive, imageUrl } = req.body;
        
        // Update the fields that are provided
        const updateData = {};
        if (name !== undefined) updateData.name = name;
        if (description !== undefined) updateData.description = description;
        if (price !== undefined) updateData.price = price;
        if (category !== undefined) updateData.category = category;
        if (tags !== undefined) updateData.tags = tags;
        if (isActive !== undefined) updateData.isActive = isActive;
        if (imageUrl !== undefined) updateData.imageUrl = imageUrl;
        updateData.updatedAt = Date.now();
        
        // Update the item
        console.log('Updating item with data:', updateData);
        const updatedItem = await Item.findByIdAndUpdate(
            req.params.id,
            { $set: updateData },
            { new: true, runValidators: true }
        );
        
        return res.status(200).json({
            success: true,
            data: updatedItem
        });
    } catch (error) {
        console.error('Error in updateItem:', error);
        return res.status(500).json({ 
            success: false,
            message: error.message 
        });
    }
};

/**
 * Delete an item
 */
exports.deleteItem = async function (req, res) {
    console.log('deleteItem function called with ID:', req.params.id);
    
    try {
        // Find the item
        const item = await Item.findById(req.params.id);
        
        if (!item) {
            console.log('Item not found');
            return res.status(404).json({
                success: false,
                message: 'Item not found'
            });
        }
        
        // Check if user has permission to delete this item
        if (item.createdBy.toString() !== req.user.id && !req.user.isAdmin) {
            console.log('User not authorized to delete this item');
            return res.status(403).json({
                success: false,
                message: 'Not authorized to delete this item'
            });
        }
        
        // Delete the item
        console.log('Deleting item...');
        await Item.findByIdAndDelete(req.params.id);
        
        return res.status(200).json({
            success: true,
            message: 'Item deleted successfully'
        });
    } catch (error) {
        console.error('Error in deleteItem:', error);
        return res.status(500).json({ 
            success: false,
            message: error.message 
        });
    }
};