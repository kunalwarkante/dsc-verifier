export default {
  async fetch(request) {
    const url = new URL(request.url);

    // =========================
    // API: PDF Upload
    // =========================
    if (url.pathname === "/api/verify" && request.method === "POST") {
      try {
        const contentType = request.headers.get("content-type") || "";

        if (!contentType.includes("multipart/form-data")) {
          return json({
            success: false,
            error: "Please upload PDF using multipart/form-data."
          }, 400);
        }

        const formData = await request.formData();
        const file = formData.get("file");

        if (!file || typeof file.arrayBuffer !== "function") {
          return json({
            success: false,
            error: "PDF file not found. Use field name: file"
          }, 400);
        }

        // 20 MB limit
        const MAX_SIZE = 20 * 1024 * 1024;

        if (file.size > MAX_SIZE) {
          return json({
            success: false,
            error: "PDF size must be below 20 MB."
          }, 413);
        }

        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);

        // Check PDF header
        const header = new TextDecoder().decode(bytes.slice(0, 8));
        const isPDF = header.startsWith("%PDF-");

        if (!isPDF) {
          return json({
            success: false,
            error: "Uploaded file is not a valid PDF."
          }, 400);
        }

        // Convert PDF bytes to searchable Latin-1 text.
        // This is only structural detection, NOT cryptographic verification.
        const pdfText = new TextDecoder("latin1").decode(bytes);

        const hasByteRange = /\/ByteRange\s*\[/.test(pdfText);
        const hasContents = /\/Contents\s*</.test(pdfText);
        const hasSignatureType = /\/Type\s*\/Sig\b/.test(pdfText);
        const hasAdobeSubFilter =
          /\/SubFilter\s*\/adbe\.pkcs7\.detached\b/.test(pdfText) ||
          /\/SubFilter\s*\/adbe\.pkcs7\.sha1\b/.test(pdfText);

        const signatureDetected =
          hasByteRange ||
          hasContents ||
          hasSignatureType ||
          hasAdobeSubFilter;

        return json({
          success: true,

          file: {
            name: file.name || "uploaded.pdf",
            size: file.size,
            type: file.type || "application/pdf"
          },

          pdf: {
            validHeader: true,
            signatureDetected
          },

          signatureStructure: {
            byteRange: hasByteRange,
            contents: hasContents,
            signatureType: hasSignatureType,
            pkcs7SubFilter: hasAdobeSubFilter
          },

          verification: {
            status: "PENDING",
            cryptographicVerification: false,
            message:
              "Digital signature structure detected. Cryptographic certificate verification is not implemented yet."
          }
        });

      } catch (error) {
        return json({
          success: false,
          error: error?.message || "Unable to process PDF."
        }, 500);
      }
    }

    // =========================
    // API status
    // =========================
    if (url.pathname === "/api/status") {
      return json({
        success: true,
        service: "DSC Verifier API",
        status: "online",
        stage: "PDF upload and signature structure detection"
      });
    }

    // =========================
    // Home
    // =========================
    return new Response(
      "DSC Verifier API - Setup OK",
      {
        headers: {
          "content-type": "text/plain; charset=UTF-8"
        }
      }
    );
  }
};


// =========================
// JSON helper
// =========================
function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}
