require('dotenv').config();  // Import and configure dotenv
const express = require('express');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Fetch API key from environment variables
const apiKey = process.env.VIRUS_TOTAL_API_KEY;

if (!apiKey) {
  console.error("API Key not found.");
  process.exit(1);
}

// Endpoint to check URL safety
app.post('/scan-url', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required." });
  }

  try {
    // Submit URL to VirusTotal
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!submitResponse.ok) throw new Error(`Failed to submit URL. Status: ${submitResponse.status}`);

    const submitData = await submitResponse.json();
    const scanId = submitData.data.id;

    // Wait for analysis to complete and fetch the result
    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
      method: "GET",
      headers: {
        "x-apikey": apiKey,
      },
    });

    if (!resultResponse.ok) throw new Error(`Failed to retrieve results. Status: ${resultResponse.status}`);
    const resultData = await resultResponse.json();

    res.json(resultData);
  } catch (error) {
    res.status(500).json({ error: error.message || "An error occurred." });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
