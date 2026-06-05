require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const http = require('http');

const app = express();
app.use(cors());
app.use(express.json());

// 🔌 الاتصال بقاعدة البيانات MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('[+] Connected to Security Database'))
    .catch(err => console.error('[-] Database Connection Error:', err));

// 📝 تعريف نموذج بيانات المستخدم المصحح (User Schema) بعد إضافة الحقول المفقودة
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: 'https://i.postimg.cc/L8g1gJ9K/hamza-developer.png' },
    isVerified: { type: Boolean, default: false },
    otpCode: { type: String, default: null },
    otpExpires: { type: Date, default: null },
    favorites: { type: [String], default: [] }, // تم الإصلاح: إضافة مصفوفة المفضلة
    totalHours: { type: Number, default: 0 }    // تم الإصلاح: إضافة حقل ساعات العمل
});
const User = mongoose.model('User', userSchema);

// 📬 إعداد محرك إرسال إيميلات الجيميل (OTP)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 🔒 برمجية وسيطة للتحقق من التوكن (تم تقديمها هنا لترتيب الكود ومنع خطأ ReferenceError)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'غير مسموح! يجب تسجيل الدخول أولاً.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'الجلسة انتهت أو التوكن غير صالح.' });
        req.userId = user.userId;
        next();
    });
};

// 🔑 1. مسار تسجيل حساب جديد وإنشاء الرمز السداسي (Register)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'جميع الحقول مطلوبة!' });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ error: 'اسم المستخدم أو البريد الإلكتروني مسجل بالفعل.' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 15 * 60 * 1000);

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            otpCode: otp,
            otpExpires
        });

        await newUser.save();

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
        user.otpCode = null;
        user.otpExpires = null;
        await user.save();

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

// 🖼️ 4. مسار رفع وتحديث الصورة الشخصية
app.post('/api/auth/update-avatar', authenticateToken, async (req, res) => {
    try {
        const { avatarData } = req.body;

        if (!avatarData) {
            return res.status(400).json({ error: 'لم يتم إرسال أي بيانات للصورة.' });
        }

        if (avatarData.length > 2 * 1024 * 1024) { 
            return res.status(400).json({ error: 'حجم الصورة كبير جداً! الحد الأقصى هو 2 ميجابايت.' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            { avatar: avatarData },
            { new: true }
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

// 🔐 5. مسار مزامنة المفضلة عند تسجيل الدخول
app.post('/api/auth/sync-favorites', authenticateToken, async (req, res) => {
    try {
        const { localFavorites } = req.body;

        if (!Array.isArray(localFavorites)) {
            return res.status(400).json({ error: 'صيغة البيانات المرسلة غير صحيحة.' });
        }

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'المستخدم غير موجود.' });

        const mergedFavorites = [...new Set([...user.favorites, ...localFavorites])];
        user.favorites = mergedFavorites;
        await user.save();

        res.status(200).json({ 
            message: 'تمت مزامنة المفضلة بنجاح مع السحاب', 
            favorites: user.favorites 
        });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ أثناء المزامنة السحابية.' });
    }
});

// ⭐ 6. مسار إضافة / إزالة أداة من المفضلة مباشرة
app.post('/api/auth/toggle-favorite', authenticateToken, async (req, res) => {
    try {
        const { toolId } = req.body;
        if (!toolId) return res.status(400).json({ error: 'معرف الأداة مطلوب.' });

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'المستخدم غير موجود.' });

        const index = user.favorites.indexOf(toolId);
        let action = '';

        if (index > -1) {
            user.favorites.splice(index, 1);
            action = 'removed';
        } else {
            user.favorites.push(toolId);
            action = 'added';
        }

        await user.save();
        res.status(200).json({ 
            message: action === 'added' ? 'تمت الإضافة للمفضلة السحابية' : 'تمت الإزالة من المفضلة السحابية',
            action,
            favorites: user.favorites 
        });
    } catch (error) {
        res.status(500).json({ error: 'فشل تعديل حالة المفضلة في السيرفر.' });
    }
});

// 📊 7. مسار جلب الإحصائيات الحية للمدخلات
app.get('/api/auth/live-stats', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });

        let activeBotsCount = 0;
        try {
            const botResponse = await fetch(`https://mc-bot-production.up.railway.app/api/user-bots-count/${user.username}`, {
                headers: { 'x-api-key': process.env.API_SECRET_KEY }
            });
            const botData = await botResponse.json();
            activeBotsCount = botData.activeCount || 0;
        } catch (botErr) {
            console.error('فشل جلب إحصائيات البوتات الحية، سيتم عرض 0 مؤقتاً');
        }

        res.status(200).json({
            activeBots: activeBotsCount,
            totalHours: user.totalHours || 0,
            savedFavorites: user.favorites ? user.favorites.length : 0
        });

    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ داخلي أثناء جلب الإحصائيات.' });
    }
});

// 🌐 إنشاء سيرفر الـ HTTP الموحد لربط الـ Express مع الـ WebSocket
const server = http.createServer(app); 
const wss = new WebSocket.Server({ server });

let connectedClients = new Set();

wss.on('connection', (ws) => {
    console.log('[+] متصفح جديد اتصل بالكونسول الحي');
    connectedClients.add(ws);

    ws.on('close', () => {
        connectedClients.delete(ws);
        console.log('[-] انقطع اتصال المتصفح بالكونسول');
    });
});

// 🎮 دالة ربط البوت بالكونسول (تستدعى عند بدء تشغيل بوت الماينكرافت)
function bindBotToConsole(bot, username) {
    bot.on('chat', (sender, message) => {
        broadcastToUser(username, {
            type: 'chat',
            timestamp: new Date().toLocaleTimeString(),
            sender: sender,
            text: message
        });
    });

    bot.on('kick', (reason) => {
        broadcastToUser(username, {
            type: 'system',
            timestamp: new Date().toLocaleTimeString(),
            text: `⚠️ تم طرد البوت بسبب: ${reason}`
        });
    });
    
    bot.on('error', (err) => {
        broadcastToUser(username, {
            type: 'error',
            timestamp: new Date().toLocaleTimeString(),
            text: `❌ خطأ في السوكيت: ${err.message}`
        });
    });
}

function broadcastToUser(targetUser, logPayload) {
    const messageString = JSON.stringify(logPayload);
    connectedClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(messageString);
        }
    });
}

// تم الإصلاح: تشغيل السيرفر الموحد (HTTP + WebSocket) على منفذ بيئة الاستضافة
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`[+] Auth Server & WebSockets securely running on port ${PORT}`);
});
