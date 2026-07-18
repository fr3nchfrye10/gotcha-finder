const functions = require('firebase-functions');
const admin = require('firebase-admin');
const cors = require('cors')({ origin: true });
const fetch = require('node-fetch');

admin.initializeApp();

const db = admin.firestore();

// API Endpoint: /analyze
exports.analyze = functions.https.onRequest((req, res) => {
  return cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Missing text parameter' });
    }

    try {
      // 1. Verify Authentication & Subscription if header is provided
      let userSubscribed = false;
      const authHeader = req.headers.authorization;

      if (authHeader && authHeader.startsWith('Bearer ')) {
        const idToken = authHeader.split('Bearer ')[1];
        try {
          const decodedToken = await admin.auth().verifyIdToken(idToken);
          const userDoc = await db.collection('users').doc(decodedToken.uid).get();
          
          if (userDoc.exists && userDoc.data().subscribed === true) {
            userSubscribed = true;
          } else {
            return res.status(403).json({ error: 'Subscription required' });
          }
        } catch (authErr) {
          return res.status(401).json({ error: 'Invalid authentication token: ' + authErr.message });
        }
      } else {
        // Unauthenticated guest scan - allowed (client enforces 1-scan limit)
        userSubscribed = true;
      }

      if (!userSubscribed) {
        return res.status(403).json({ error: 'Access denied: Subscription required' });
      }

      // 2. Invoke Gemini API securely using secret environment variable
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return res.status(500).json({ error: 'Server configuration error: Gemini API Key not set' });
      }

      const systemPrompt = `You are an expert contract lawyer specialized in freelance, consulting, and independent contractor agreements.
Analyze the following contract text. Identify and flag clauses that pose risks, gotchas, or unfavorable terms for the Freelancer.
Group findings into four categories: 'Payment & Billing', 'Liability & Indemnity', 'Intellectual Property', or 'Termination & Scope'.
Rate the riskLevel as 'High', 'Medium', or 'Low'.
For each finding, extract the exact originalText from the contract (must match a substring in the contract verbatim), summarize the concern, and provide a clear negotiation strategy/rephrasing.`;

      const requestPayload = {
        contents: [{
          parts: [
            { text: systemPrompt },
            { text: `Contract text to analyze:\n\n${text}` }
          ]
        }],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: {
            type: "OBJECT",
            properties: {
              findings: {
                type: "ARRAY",
                items: {
                  type: "OBJECT",
                  properties: {
                    category: { type: "STRING", enum: ["Payment & Billing", "Liability & Indemnity", "Intellectual Property", "Termination & Scope"] },
                    riskLevel: { type: "STRING", enum: ["High", "Medium", "Low"] },
                    summary: { type: "STRING" },
                    originalText: { type: "STRING" },
                    explanation: { type: "STRING" }
                  },
                  required: ["category", "riskLevel", "summary", "originalText", "explanation"]
                }
              }
            }
          }
        }
      };

      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestPayload)
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Gemini API error: ${errText}`);
      }

      const data = await response.json();
      const candidateText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!candidateText) {
        throw new Error("No candidates returned from Gemini");
      }

      return res.status(200).json(JSON.parse(candidateText.trim()));
    } catch (err) {
      console.error('API Error:', err);
      return res.status(500).json({ error: err.message });
    }
  });
});

// Stripe Checkout Session Generator
exports.createCheckoutSession = functions.https.onRequest((req, res) => {
  return cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const idToken = authHeader.split('Bearer ')[1];
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(idToken);
    } catch (authErr) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const stripeSecret = process.env.STRIPE_SECRET_KEY;
    if (!stripeSecret) {
      return res.status(500).json({ error: 'Stripe configuration error' });
    }

    const stripe = require('stripe')(stripeSecret);

    try {
      const origin = req.headers.origin || 'http://localhost:5000';

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: {
              name: 'GotchaFinder Premium Plan',
              description: 'Unlimited freelance contract risk audits',
            },
            unit_amount: 900,
            recurring: {
              interval: 'month',
            },
          },
          quantity: 1,
        }],
        mode: 'subscription',
        success_url: `${origin}/?payment=success`,
        cancel_url: `${origin}/?payment=cancel`,
        client_reference_id: decodedToken.uid,
      });

      return res.status(200).json({ url: session.url });
    } catch (err) {
      console.error('Stripe session creation error:', err);
      return res.status(500).json({ error: err.message });
    }
  });
});

// Stripe Webhook Endpoint
exports.stripeWebhook = functions.https.onRequest(async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const stripeSecret = process.env.STRIPE_SECRET_KEY;

  if (!sig || !webhookSecret || !stripeSecret) {
    console.error('Webhook verification configuration missing.');
    return res.status(400).send('Webhook configuration missing');
  }

  const stripe = require('stripe')(stripeSecret);
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const uid = session.client_reference_id;
    
    if (uid) {
      try {
        await db.collection('users').doc(uid).set({
          subscribed: true,
          stripeCustomerId: session.customer,
          subscriptionId: session.subscription,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        
        console.log(`Successfully upgraded user ${uid} to Premium subscription.`);
      } catch (dbErr) {
        console.error(`Database error saving subscription status for user ${uid}:`, dbErr);
        return res.status(500).send('Database storage error');
      }
    } else {
      console.warn('Stripe checkout completed but client_reference_id (uid) was missing.');
    }
  }

  return res.status(200).json({ received: true });
});
