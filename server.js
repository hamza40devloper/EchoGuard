require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

// 🔌 الاتصال بقاعدة البيانات (MongoDB كمثال وهي الأفضل لحفظ الحسابات والمفضلات)
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('[+] Connected to Security Database'))
    .catch(err => console.error('[-] Database Connection Error:', err));

// 📝 تعريف نموذج بيانات المستخدم (User Schema)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: 'https://i.postimg.cc/L8g1gJ9K/hamza-developer.png' },
    isVerified: { type: Boolean, default: false },
    otpCode: { type: String, default: null },
    otpExpires: { type: Date, default: null }
});
const User = mongoose.model('User', userSchema);

// 📬 إعداد محرك إرسال إيميلات الجيميل (OTP)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // إيميل الجيميل الخاص بك
        pass: process.env.EMAIL_PASS  // رمز تطبيق الجيميل (App Password) وليس الباسورد العادي
    }
});

// 🔑 1. مسار تسجيل حساب جديد وإنشاء الرمز السداسي (Register)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // التحقق من المدخلات لمنع الثغرات
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'جميع الحقول مطلوبة!' });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ error: 'اسم المستخدم أو البريد الإلكتروني مسجل بالفعل.' });
        }

        // تشفير كلمة المرور بقوة 12 بت لمنع فك التشفير من الهاكرز
        const hashedPassword = await bcrypt.hash(password, 12);

        // توليد رمز سداسي عشوائي
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // صلاحية الرمز 15 دقيقة

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            otpCode: otp,
            otpExpires
        });

        await newUser.save();

        // إرسال الرمز السداسي إلى بريد المستخدم
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: '🔏 رمز التحقق لمنصة NONETWORK',
            html: `<h3>مرحباً ${username}،</h3>
                   <p>رمز التحقق السداسي الخاص بك لتفعيل الحساب هو:</p>
                   <h1 style="color: #58a6ff; font-family: monospace; letter-spacing: 5px;">${otp}</h1>
                   <p>هذا الرمز صالح لمدة 15 دقيقة فقط.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.status(201).json({ message: 'تم تسجيل الحساب بنجاح. يرجى التحقق من بريدك الإلكتروني.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'حدث خطأ داخلي في السيرفر.' });
    }
});

// 📩 2. مسار تفعيل الحساب عبر الرمز السداسي (Verify OTP)
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otpCode !== otp || user.otpExpires < new Date()) {
            return res.status(400).json({ error: 'الرمز السداسي خاطئ أو انتهت صلاحيته.' });
        }

        user.isVerified = true;
        user.otpCode = null; // تنظيف الرمز بعد التحقق
        user.otpExpires = null;
        await user.save();

        // إنشاء توكن أمان (JWT) صالح لمدة 7 أيام للولوج التلقائي
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.status(200).json({ 
            message: 'تم تفعيل الحساب بنجاح!', 
            token,
            user: { username: user.username, email: user.email, avatar: user.avatar }
        });
    } catch (error) {
        res.status(500).json({ error: 'خطأ أثناء عملية التحقق.' });
    }
});

// 🔐 3. مسار تسجيل الدخول للحسابات المفعلة (Login)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !user.isVerified) {
            return res.status(400).json({ error: 'الحساب غير موجود أو لم يتم تفعيله عبر البريد بعد.' });
        }

        // مقارنة الهاش المشفر
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'بيانات الاعتماد غير صحيحة.' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.status(200).json({ 
            token, 
            user: { username: user.username, email: user.email, avatar: user.avatar } 
        });
    } catch (error) {
        res.status(500).json({ error: 'خطأ في خادم تسجيل الدخول.' });
    }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`[+] Auth Server securely running on port ${PORT}`));
// برمجية وسيطة (Middleware) للتحقق من التوكن وحماية المسار من الاختراق
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // جلب التوكن من الهيدر

    if (!token) {
        return res.status(401).json({ error: 'غير مسموح! يجب تسجيل الدخول أولاً.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'الجلسة انتهت أو التوكن غير صالح.' });
        req.userId = user.userId; // تمرير معرف المستخدم للمسار التالي
        next();
    });
};

// 🖼️ مسار رفع وتحديث الصورة الشخصية (محمي تماماً)
app.post('/api/auth/update-avatar', authenticateToken, async (req, res) => {
    try {
        const { avatarData } = req.body; // استقبال الصورة كـ Base64 من الواجهة

        if (!avatarData) {
            return res.status(400).json({ error: 'لم يتم إرسال أي بيانات للصورة.' });
        }

        // الحماية: التحقق من حجم السلسلة النصية لمنع رفع ملفات ضخمة تستهلك الذاكرة
        if (avatarData.length > 2 * 1024 * 1024) { 
            return res.status(400).json({ error: 'حجم الصورة كبير جداً! الحد الأقصى هو 2 ميجابايت.' });
        }

        // البحث عن المستخدم وتحديث الصورة في قاعدة البيانات
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            { avatar: avatarData },
            { new: true } // إرجاع البيانات الجديدة بعد التحديث
        );

        if (!updatedUser) {
            return res.status(404).json({ error: 'المستخدم غير موجود.' });
        }

        res.status(200).json({ 
            message: 'تم تحديث الصورة الشخصية بنجاح!',
            avatar: updatedUser.avatar
        });

    } catch (error) {
        console.error('Avatar Upload Error:', error);
        res.status(500).json({ error: 'حدث خطأ داخلي أثناء حفظ الصورة.' });
    }
});
