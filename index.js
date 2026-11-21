import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
import { MongoClient, ObjectId } from 'mongodb';

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'equiprent_dev_jwt_secret_change_in_prod';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

app.use(
  cors({
    origin: [CLIENT_URL, 'http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true,
  })
);
app.use(express.json());

// MongoDB Connection
const mongoUri = process.env.BETTER_AUTH_DB_URL;
if (!mongoUri) {
  console.error('Missing BETTER_AUTH_DB_URL in environment variables.');
}

const client = new MongoClient(mongoUri);
const db = client.db('equipmentRentalDB');

const usersCollection = db.collection('users');
const equipmentsCollection = db.collection('equipment');
const bookingsCollection = db.collection('bookings');
const favoritesCollection = db.collection('favorites');
const paymentsCollection = db.collection('payments');

async function connectToMongoDB() {
  try {
    await client.connect();
    console.log('Successfully connected to MongoDB!');
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
}

await connectToMongoDB();

// Helpers
function toObjectId(id) {
  if (!id || typeof id !== 'string') return null;
  return ObjectId.isValid(id) ? new ObjectId(id) : null;
}

function normalizeRole(role) {
  const val = String(role || 'Customer').trim().toLowerCase();
  if (val === 'admin') return 'Admin';
  if (val === 'owner') return 'Owner';
  return 'Customer';
}

function signAccessToken(user) {
  return jwt.sign(
    {
      id: user._id?.toString(),
      email: user.email,
      name: user.name || '',
      role: normalizeRole(user.role),
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ==========================================
// RBAC & JWT Middlewares
// ==========================================
export const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || '';
    const tokenFromHeader = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : null;
    const token = tokenFromHeader || req.cookies?.token || null;

    if (!token) {
      return res.status(401).json({ message: 'Unauthorized: Missing access token.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    let dbUser = null;

    if (decoded?.email) {
      dbUser = await usersCollection.findOne({ email: decoded.email.toLowerCase() });
    }

    if (dbUser?.status === 'Suspended') {
      return res.status(403).json({ message: 'Forbidden: Account is suspended.' });
    }

    req.user = {
      id: dbUser?._id?.toString() || decoded.id,
      email: (dbUser?.email || decoded.email || '').toLowerCase(),
      name: dbUser?.name || decoded.name || '',
      role: normalizeRole(dbUser?.role || decoded.role),
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: 'Unauthorized: Invalid or expired token.' });
  }
};

export const verifyRenter = (req, res, next) => {
  const role = normalizeRole(req.user?.role);
  if (role === 'Customer' || role === 'Admin') {
    return next();
  }
  return res.status(403).json({ message: 'Forbidden: Customer/Renter access required.' });
};

export const verifyCustomer = verifyRenter;

export const verifyOwner = (req, res, next) => {
  const role = normalizeRole(req.user?.role);
  if (role === 'Owner' || role === 'Admin') {
    return next();
  }
  return res.status(403).json({ message: 'Forbidden: Owner access required.' });
};

export const verifyAdmin = (req, res, next) => {
  const role = normalizeRole(req.user?.role);
  if (role === 'Admin') {
    return next();
  }
  return res.status(403).json({ message: 'Forbidden: Admin access required.' });
};

// ==========================================
// Root & Auth / JWT Endpoints
// ==========================================
app.get('/', (req, res) => {
  res.send('Equipment Rental Platform API Server is running!');
});

// Register / Sync user (default role: Customer)
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, image, phone, address } = req.body || {};
    if (!email) {
      return res.status(400).json({ message: 'Email is required.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const existing = await usersCollection.findOne({ email: cleanEmail });

    if (existing) {
      const token = signAccessToken(existing);
      return res.status(200).json({
        message: 'User already exists.',
        token,
        user: existing,
      });
    }

    const newUser = {
      name: String(name || 'Customer').trim(),
      email: cleanEmail,
      image: String(image || '').trim(),
      phone: String(phone || '').trim(),
      address: String(address || '').trim(),
      role: 'Customer',
      status: 'Active',
      createdAt: new Date().toISOString(),
    };

    const insertResult = await usersCollection.insertOne(newUser);
    const savedUser = { _id: insertResult.insertedId, ...newUser };
    const token = signAccessToken(savedUser);

    res.status(201).json({
      message: 'User registered successfully.',
      token,
      user: savedUser,
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Failed to register user.' });
  }
});

// Issue JWT access token after Better Auth login / Google sign-in
app.post('/api/auth/jwt', async (req, res) => {
  try {
    const { email, name, image } = req.body || {};
    if (!email) {
      return res.status(400).json({ message: 'Email is required to issue token.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    let user = await usersCollection.findOne({ email: cleanEmail });

    if (!user) {
      const newUser = {
        name: String(name || cleanEmail.split('@')[0]).trim(),
        email: cleanEmail,
        image: String(image || '').trim(),
        phone: '',
        address: '',
        role: 'Customer',
        status: 'Active',
        createdAt: new Date().toISOString(),
      };
      const inserted = await usersCollection.insertOne(newUser);
      user = { _id: inserted.insertedId, ...newUser };
    }

    if (user.status === 'Suspended') {
      return res.status(403).json({ message: 'Your account is suspended.' });
    }

    const token = signAccessToken(user);
    res.json({
      token,
      accessToken: token,
      role: normalizeRole(user.role),
      user,
    });
  } catch (err) {
    console.error('JWT issue error:', err);
    res.status(500).json({ message: 'Failed to generate access token.' });
  }
});

// ==========================================
// Profile Endpoints (Customer, Owner, Admin)
// ==========================================
app.get('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ message: 'User profile not found.' });
    }
    res.json({ data: user });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load profile.' });
  }
});

app.patch('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const { name, image, phone, address } = req.body || {};
    const updateDoc = {
      $set: {
        ...(name !== undefined ? { name: String(name).trim() } : {}),
        ...(image !== undefined ? { image: String(image).trim() } : {}),
        ...(phone !== undefined ? { phone: String(phone).trim() } : {}),
        ...(address !== undefined ? { address: String(address).trim() } : {}),
        updatedAt: new Date().toISOString(),
      },
    };

    const result = await usersCollection.findOneAndUpdate(
      { email: req.user.email },
      updateDoc,
      { returnDocument: 'after', upsert: true }
    );

    res.json({ message: 'Profile updated successfully.', data: result });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update profile.' });
  }
});

// ==========================================
// Equipment Endpoints (Public + Owner + Admin)
// ==========================================
// Public: Featured approved equipment (default limit 6)
app.get('/api/equipment/featured', async (req, res) => {
  try {
    const limit = Math.min(20, Math.max(1, Number(req.query.limit) || 6));
    const items = await equipmentsCollection
      .find({ status: 'Approved' })
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();
    res.json({ data: items });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch featured equipment.' });
  }
});

// Public: All approved equipment with server-side search, filter, sort, pagination
app.get('/api/equipment', async (req, res) => {
  try {
    const {
      search = '',
      category = '',
      location = '',
      rentalType = '',
      minPrice = '',
      maxPrice = '',
      availability = '',
      sort = 'newest',
      page = '1',
      limit = '9',
    } = req.query;

    const query = { status: 'Approved' };

    if (String(search).trim()) {
      const regex = new RegExp(String(search).trim(), 'i');
      query.$or = [{ name: regex }, { category: regex }, { brand: regex }, { model: regex }];
    }

    if (category && category !== 'All') {
      query.category = category;
    }

    if (String(location).trim()) {
      query.location = new RegExp(String(location).trim(), 'i');
    }

    if (rentalType && rentalType !== 'All') {
      query.rentalType = rentalType;
    }

    if (minPrice !== '' || maxPrice !== '') {
      query.rentalPrice = {};
      if (minPrice !== '' && !Number.isNaN(Number(minPrice))) {
        query.rentalPrice.$gte = Number(minPrice);
      }
      if (maxPrice !== '' && !Number.isNaN(Number(maxPrice))) {
        query.rentalPrice.$lte = Number(maxPrice);
      }
      if (Object.keys(query.rentalPrice).length === 0) {
        delete query.rentalPrice;
      }
    }

    if (availability === 'available') {
      query.availableQuantity = { $gt: 0 };
    } else if (availability === 'booked') {
      query.availableQuantity = { $lte: 0 };
    }

    let sortOption = { createdAt: -1 };
    if (sort === 'price_asc') sortOption = { rentalPrice: 1 };
    if (sort === 'price_desc') sortOption = { rentalPrice: -1 };
    if (sort === 'newest') sortOption = { createdAt: -1 };

    const pageNum = Math.max(1, Number(page) || 1);
    const limitNum = Math.min(50, Math.max(1, Number(limit) || 9));
    const skip = (pageNum - 1) * limitNum;

    const totalCount = await equipmentsCollection.countDocuments(query);
    const items = await equipmentsCollection
      .find(query)
      .sort(sortOption)
      .skip(skip)
      .limit(limitNum)
      .toArray();

    res.json({
      data: items,
      pagination: {
        totalCount,
        totalPages: Math.max(1, Math.ceil(totalCount / limitNum)),
        currentPage: pageNum,
        limit: limitNum,
      },
    });
  } catch (err) {
    console.error('GET /api/equipment error:', err);
    res.status(500).json({ message: 'Failed to fetch equipment.' });
  }
});

// Owner: Equipment added by logged-in owner
app.get('/api/equipment/owner', verifyToken, verifyOwner, async (req, res) => {
  try {
    const email = (req.query.email || req.user.email || '').toLowerCase();
    const filter =
      req.user.role === 'Admin' && !req.query.email
        ? {}
        : {
            $or: [{ ownerEmail: email }, { 'owner.email': email }],
          };

    const items = await equipmentsCollection.find(filter).sort({ createdAt: -1 }).toArray();
    res.json({ data: items });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch owner equipment.' });
  }
});

// Admin: All equipment regardless of status
app.get('/api/equipment/admin/all', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const items = await equipmentsCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ data: items });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch all equipment.' });
  }
});

// Single equipment details
app.get('/api/equipment/:id', async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const item = oid
      ? await equipmentsCollection.findOne({ _id: oid })
      : await equipmentsCollection.findOne({ _id: req.params.id });

    if (!item) {
      return res.status(404).json({ message: 'Equipment not found.' });
    }
    res.json({ data: item });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch equipment details.' });
  }
});

// Owner: Add new equipment (default status: Pending)
app.post('/api/equipment', verifyToken, verifyOwner, async (req, res) => {
  try {
    const body = req.body || {};
    if (!body.name || !body.category || !body.location || !body.rentalPrice) {
      return res.status(400).json({ message: 'Required equipment fields are missing.' });
    }

    const ownerEmail = (body.ownerEmail || body.owner?.email || req.user.email).toLowerCase();
    const newEquipment = {
      name: String(body.name).trim(),
      description: String(body.description || '').trim(),
      category: String(body.category).trim(),
      location: String(body.location).trim(),
      rentalPrice: Number(body.rentalPrice),
      rentalType: body.rentalType || 'Daily',
      availableQuantity: Math.max(0, Number(body.availableQuantity ?? 1)),
      condition: body.condition || 'Good',
      brand: String(body.brand || '').trim(),
      model: String(body.model || '').trim(),
      image: String(body.image || '').trim(),
      termsAndConditions: String(body.termsAndConditions || '').trim(),
      status: 'Pending',
      ownerEmail,
      owner: {
        name: body.owner?.name || req.user.name || 'Equipment Owner',
        email: ownerEmail,
        phone: body.owner?.phone || '',
      },
      createdAt: new Date().toISOString(),
    };

    const result = await equipmentsCollection.insertOne(newEquipment);
    res.status(201).json({
      message: 'Equipment submitted with Pending status.',
      data: { _id: result.insertedId, ...newEquipment },
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to create equipment.' });
  }
});

// Owner/Admin: Update equipment
app.patch('/api/equipment/:id', verifyToken, verifyOwner, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    if (!oid) {
      return res.status(400).json({ message: 'Invalid equipment ID.' });
    }

    const existing = await equipmentsCollection.findOne({ _id: oid });
    if (!existing) {
      return res.status(404).json({ message: 'Equipment not found.' });
    }

    const isOwner =
      (existing.ownerEmail || existing.owner?.email || '').toLowerCase() === req.user.email;
    if (req.user.role !== 'Admin' && !isOwner) {
      return res.status(403).json({ message: 'Forbidden: You do not own this item.' });
    }

    const allowed = {};
    const fields = [
      'name',
      'description',
      'category',
      'location',
      'rentalPrice',
      'rentalType',
      'availableQuantity',
      'condition',
      'brand',
      'model',
      'image',
      'termsAndConditions',
    ];

    for (const key of fields) {
      if (req.body[key] !== undefined) {
        allowed[key] =
          key === 'rentalPrice' || key === 'availableQuantity'
            ? Number(req.body[key])
            : req.body[key];
      }
    }

    if (req.user.role === 'Admin' && req.body.status) {
      allowed.status = req.body.status;
    }

    allowed.updatedAt = new Date().toISOString();

    const updated = await equipmentsCollection.findOneAndUpdate(
      { _id: oid },
      { $set: allowed },
      { returnDocument: 'after' }
    );

    res.json({ message: 'Equipment updated.', data: updated });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update equipment.' });
  }
});

// Admin: Approve or Reject equipment
app.patch('/api/equipment/:id/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const { status } = req.body || {};
    if (!oid || !['Pending', 'Approved', 'Rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid ID or status value.' });
    }

    const updated = await equipmentsCollection.findOneAndUpdate(
      { _id: oid },
      { $set: { status, updatedAt: new Date().toISOString() } },
      { returnDocument: 'after' }
    );

    if (!updated) {
      return res.status(404).json({ message: 'Equipment not found.' });
    }

    res.json({ message: `Equipment status updated to ${status}.`, data: updated });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update equipment status.' });
  }
});

// Owner/Admin: Delete equipment
app.delete('/api/equipment/:id', verifyToken, verifyOwner, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    if (!oid) {
      return res.status(400).json({ message: 'Invalid equipment ID.' });
    }

    const existing = await equipmentsCollection.findOne({ _id: oid });
    if (!existing) {
      return res.status(404).json({ message: 'Equipment not found.' });
    }

    const isOwner =
      (existing.ownerEmail || existing.owner?.email || '').toLowerCase() === req.user.email;
    if (req.user.role !== 'Admin' && !isOwner) {
      return res.status(403).json({ message: 'Forbidden: You cannot delete this item.' });
    }

    await equipmentsCollection.deleteOne({ _id: oid });
    res.json({ message: 'Equipment deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete equipment.' });
  }
});

// ==========================================
// Favorites Endpoints (Customer / Renter)
// ==========================================
app.get('/api/favorites', verifyToken, verifyRenter, async (req, res) => {
  try {
    const email = (req.query.email || req.user.email).toLowerCase();
    const items = await favoritesCollection
      .find({ userEmail: email })
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ data: items });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch favorites.' });
  }
});

app.post('/api/favorites', verifyToken, verifyRenter, async (req, res) => {
  try {
    const { equipmentId, equipmentName, category, location, rentalPrice, rentalType, availableQuantity, image } =
      req.body || {};
    if (!equipmentId) {
      return res.status(400).json({ message: 'equipmentId is required.' });
    }

    const existing = await favoritesCollection.findOne({
      userEmail: req.user.email,
      equipmentId: String(equipmentId),
    });

    if (existing) {
      return res.status(200).json({ message: 'Already in favorites.', data: existing });
    }

    const doc = {
      userEmail: req.user.email,
      equipmentId: String(equipmentId),
      equipmentName: equipmentName || 'Equipment',
      category: category || '',
      location: location || '',
      rentalPrice: Number(rentalPrice || 0),
      rentalType: rentalType || 'Daily',
      availableQuantity: Number(availableQuantity ?? 1),
      image: image || '',
      createdAt: new Date().toISOString(),
    };

    const inserted = await favoritesCollection.insertOne(doc);
    res.status(201).json({ message: 'Added to favorites.', data: { _id: inserted.insertedId, ...doc } });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add favorite.' });
  }
});

app.delete('/api/favorites/:id', verifyToken, verifyRenter, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const filter = oid
      ? { _id: oid, userEmail: req.user.email }
      : { equipmentId: req.params.id, userEmail: req.user.email };

    const deleted = await favoritesCollection.findOneAndDelete(filter);
    if (!deleted) {
      return res.status(404).json({ message: 'Favorite item not found.' });
    }
    res.json({ message: 'Removed from favorites.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to remove favorite.' });
  }
});

// ==========================================
// Bookings & Stripe Payment Endpoints
// ==========================================
// Customer: My rentals
app.get('/api/bookings/my-rentals', verifyToken, verifyRenter, async (req, res) => {
  try {
    const email = (req.query.email || req.user.email).toLowerCase();
    const list = await bookingsCollection
      .find({ customerEmail: email })
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ data: list });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch my rentals.' });
  }
});

// Owner: Rentals on owner's equipment
app.get('/api/bookings/owner-rentals', verifyToken, verifyOwner, async (req, res) => {
  try {
    const email = (req.query.email || req.user.email).toLowerCase();
    const list = await bookingsCollection
      .find({ ownerEmail: email })
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ data: list });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch owner rentals.' });
  }
});

// Admin: All rental bookings
app.get('/api/bookings/admin/all', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const list = await bookingsCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ data: list });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch all rentals.' });
  }
});

// Create booking (Pending payment)
app.post('/api/bookings', verifyToken, verifyRenter, async (req, res) => {
  try {
    const body = req.body || {};
    const qty = Math.max(1, Number(body.requiredQuantity || 1));
    const totalAmount = Number(body.totalAmount || 0);

    if (!body.equipmentId || !body.startDate || !body.endDate || totalAmount <= 0) {
      return res.status(400).json({ message: 'Invalid booking details.' });
    }

    const bookingDoc = {
      equipmentId: String(body.equipmentId),
      equipmentName: body.equipmentName || 'Equipment',
      category: body.category || '',
      ownerName: body.ownerName || 'Equipment Owner',
      ownerEmail: String(body.ownerEmail || '').toLowerCase(),
      customerName: body.customerName || req.user.name || 'Customer',
      customerEmail: req.user.email,
      contactNumber: body.contactNumber || '',
      deliveryAddress: body.deliveryAddress || '',
      additionalNotes: body.additionalNotes || '',
      startDate: body.startDate,
      endDate: body.endDate,
      durationLabel: body.durationLabel || '',
      requiredQuantity: qty,
      totalAmount,
      bookingAmount: totalAmount,
      paymentStatus: 'Pending',
      bookingStatus: 'Pending',
      bookingDate: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };

    const result = await bookingsCollection.insertOne(bookingDoc);
    res.status(201).json({
      message: 'Booking created.',
      bookingId: result.insertedId,
      data: { _id: result.insertedId, ...bookingDoc },
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to create booking.' });
  }
});

// Owner/Admin: Update booking status
app.patch('/api/bookings/:id/status', verifyToken, verifyOwner, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const { bookingStatus } = req.body || {};
    const allowedStatuses = ['Pending', 'Confirmed', 'Completed', 'Cancelled'];

    if (!oid || !allowedStatuses.includes(bookingStatus)) {
      return res.status(400).json({ message: 'Invalid booking ID or status.' });
    }

    const updated = await bookingsCollection.findOneAndUpdate(
      { _id: oid },
      { $set: { bookingStatus, updatedAt: new Date().toISOString() } },
      { returnDocument: 'after' }
    );

    if (!updated) {
      return res.status(404).json({ message: 'Booking not found.' });
    }

    res.json({ message: 'Booking status updated.', data: updated });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update booking status.' });
  }
});

// Stripe: Create Checkout Session
app.post('/api/payments/create-checkout-session', verifyToken, verifyRenter, async (req, res) => {
  try {
    const body = req.body || {};
    const amount = Number(body.totalAmount || body.bookingAmount || 0);

    if (amount <= 0) {
      return res.status(400).json({ message: 'Valid rental amount is required.' });
    }

    const successUrl =
      body.successUrl || `${CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = body.cancelUrl || `${CLIENT_URL}/payment/cancel`;

    if (stripe) {
      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        payment_method_types: ['card'],
        customer_email: req.user.email,
        line_items: [
          {
            price_data: {
              currency: 'bdt',
              product_data: {
                name: body.equipmentName || 'Equipment Rental',
                description: `Qty: ${body.requiredQuantity || 1} | ${body.startDate || ''} to ${body.endDate || ''}`,
              },
              unit_amount: Math.round(amount * 100),
            },
            quantity: 1,
          },
        ],
        metadata: {
          bookingId: String(body.bookingId || ''),
          equipmentId: String(body.equipmentId || ''),
          customerEmail: req.user.email,
        },
        success_url: successUrl.includes('{CHECKOUT_SESSION_ID}')
          ? successUrl
          : `${successUrl}?session_id={CHECKOUT_SESSION_ID}&amount=${amount}`,
        cancel_url: cancelUrl,
      });

      return res.json({ url: session.url, sessionId: session.id });
    }

    const mockSessionId = `cs_test_${Date.now()}`;
    res.json({
      sessionId: mockSessionId,
      transactionId: mockSessionId,
      url: null,
    });
  } catch (err) {
    console.error('Stripe checkout session error:', err);
    res.status(500).json({ message: 'Failed to create Stripe checkout session.' });
  }
});

// Stripe: Confirm payment, update booking & record transaction in payments collection
app.post('/api/payments/confirm', verifyToken, verifyRenter, async (req, res) => {
  try {
    const { sessionId, bookingDraft, totalAmount } = req.body || {};
    const txnId = sessionId || `txn_${Date.now()}`;
    const paidAmount = Number(totalAmount ?? bookingDraft?.totalAmount ?? 0);

    let bookingRecord = null;
    const draftBookingId = toObjectId(bookingDraft?.bookingId);

    if (draftBookingId) {
      bookingRecord = await bookingsCollection.findOneAndUpdate(
        { _id: draftBookingId },
        {
          $set: {
            paymentStatus: 'Paid',
            bookingStatus: 'Confirmed',
            transactionId: txnId,
            paidAt: new Date().toISOString(),
          },
        },
        { returnDocument: 'after' }
      );
    }

    if (!bookingRecord && bookingDraft) {
      const newBooking = {
        equipmentId: String(bookingDraft.equipmentId || ''),
        equipmentName: bookingDraft.equipmentName || 'Rented Equipment',
        category: bookingDraft.category || '',
        ownerName: bookingDraft.ownerName || 'Equipment Owner',
        ownerEmail: String(bookingDraft.ownerEmail || '').toLowerCase(),
        customerName: req.user.name || bookingDraft.customerName || 'Customer',
        customerEmail: req.user.email,
        contactNumber: bookingDraft.contactNumber || '',
        deliveryAddress: bookingDraft.deliveryAddress || '',
        additionalNotes: bookingDraft.additionalNotes || '',
        startDate: bookingDraft.startDate || '',
        endDate: bookingDraft.endDate || '',
        durationLabel: bookingDraft.durationLabel || '',
        requiredQuantity: Number(bookingDraft.requiredQuantity || 1),
        totalAmount: paidAmount,
        bookingAmount: paidAmount,
        paymentStatus: 'Paid',
        bookingStatus: 'Confirmed',
        transactionId: txnId,
        bookingDate: new Date().toISOString(),
        paidAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
      const ins = await bookingsCollection.insertOne(newBooking);
      bookingRecord = { _id: ins.insertedId, ...newBooking };
    }

    const paymentDoc = {
      transactionId: txnId,
      bookingId: bookingRecord?._id?.toString() || bookingDraft?.bookingId || null,
      equipmentName: bookingRecord?.equipmentName || bookingDraft?.equipmentName || 'Rented Equipment',
      customerEmail: req.user.email,
      ownerEmail: bookingRecord?.ownerEmail || bookingDraft?.ownerEmail || '',
      amount: paidAmount,
      currency: 'BDT',
      paymentStatus: 'Paid',
      paidAt: new Date().toISOString(),
    };

    await paymentsCollection.insertOne(paymentDoc);

    res.json({
      message: 'Payment confirmed and booking recorded.',
      data: {
        ...(bookingRecord || {}),
        transactionId: txnId,
        totalAmount: paidAmount,
        paymentStatus: 'Paid',
        bookingStatus: 'Confirmed',
      },
    });
  } catch (err) {
    console.error('Payment confirm error:', err);
    res.status(500).json({ message: 'Failed to confirm payment.' });
  }
});

// ==========================================
// Admin: Users & Role Management
// ==========================================
app.get('/api/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ data: users });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch users.' });
  }
});

app.patch('/api/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const role = normalizeRole(req.body?.role);
    if (!oid) {
      return res.status(400).json({ message: 'Invalid user ID.' });
    }

    const updated = await usersCollection.findOneAndUpdate(
      { _id: oid },
      { $set: { role, updatedAt: new Date().toISOString() } },
      { returnDocument: 'after' }
    );

    if (!updated) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({ message: `User role updated to ${role}.`, data: updated });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user role.' });
  }
});

app.patch('/api/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    if (!oid) {
      return res.status(400).json({ message: 'Invalid user ID.' });
    }

    const updateFields = { updatedAt: new Date().toISOString() };
    if (req.body?.role) {
      updateFields.role = normalizeRole(req.body.role);
    }
    if (req.body?.status && ['Active', 'Suspended'].includes(req.body.status)) {
      updateFields.status = req.body.status;
    }

    const updated = await usersCollection.findOneAndUpdate(
      { _id: oid },
      { $set: updateFields },
      { returnDocument: 'after' }
    );

    if (!updated) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({ message: 'User updated.', data: updated });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user.' });
  }
});

// ==========================================
// Admin & Owner Analytics Endpoints
// ==========================================
app.get('/api/analytics/admin', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [totalUsers, totalEquipment, totalBookings, pendingApprovals, completedRentals] =
      await Promise.all([
        usersCollection.countDocuments({}),
        equipmentsCollection.countDocuments({}),
        bookingsCollection.countDocuments({}),
        equipmentsCollection.countDocuments({ status: 'Pending' }),
        bookingsCollection.countDocuments({ bookingStatus: 'Completed' }),
      ]);

    const paidBookings = await bookingsCollection
      .find({ paymentStatus: { $in: ['Paid', 'Succeeded'] } })
      .toArray();

    const totalRevenue = paidBookings.reduce(
      (sum, b) => sum + Number(b.totalAmount ?? b.bookingAmount ?? 0),
      0
    );

    res.json({
      totalUsers,
      totalEquipment,
      totalBookings,
      pendingApprovals,
      completedRentals,
      totalRevenue,
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load admin analytics.' });
  }
});

app.get('/api/analytics/owner', verifyToken, verifyOwner, async (req, res) => {
  try {
    const email = (req.query.email || req.user.email).toLowerCase();
    const ownerFilter = { $or: [{ ownerEmail: email }, { 'owner.email': email }] };

    const [totalListedEquipment, ownerBookings] = await Promise.all([
      equipmentsCollection.countDocuments(ownerFilter),
      bookingsCollection.find({ ownerEmail: email }).toArray(),
    ]);

    const completedRentals = ownerBookings.filter(
      (b) => String(b.bookingStatus).toLowerCase() === 'completed'
    ).length;

    const totalEarnings = ownerBookings
      .filter((b) => ['paid', 'succeeded'].includes(String(b.paymentStatus).toLowerCase()))
      .reduce((sum, b) => sum + Number(b.bookingAmount ?? b.totalAmount ?? 0), 0);

    res.json({
      totalListedEquipment,
      completedRentals,
      totalEarnings,
      totalBookings: ownerBookings.length,
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load owner analytics.' });
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

export default app;