// api/claude.js
// Fonction serverless Vercel : proxy sécurisé vers l'API Anthropic.
// Le navigateur appelle CETTE fonction (/api/claude), jamais api.anthropic.com directement.
// La clé API reste secrète, stockée dans les variables d'environnement Vercel.

export default async function handler(req, res) {
  // On n'accepte que les requêtes POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Méthode non autorisée" });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      error: "La variable ANTHROPIC_API_KEY n'est pas configurée sur Vercel.",
    });
  }

  try {
    // req.body est déjà parsé en JSON par Vercel quand Content-Type = application/json
    const anthropicResponse = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(req.body),
    });

    const data = await anthropicResponse.json();
    // On renvoie tel quel au front, avec le même code HTTP
    return res.status(anthropicResponse.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: "Erreur proxy: " + e.message });
  }
}
