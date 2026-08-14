import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

// ============================================================
// PKI.JS CRYPTO ENGINE
// Cloudflare Workers WebCrypto
// ============================================================

pkijs.setEngine(
  "CloudflareWebCrypto",
  new pkijs.CryptoEngine({
    name: "CloudflareWebCrypto",
    crypto: crypto,
    subtle: crypto.subtle
  })
);


// ============================================================
// WORKER
// ============================================================

export default {

  async fetch(request) {

    const url = new URL(request.url);

    // ========================================================
    // PDF VERIFY API
    // ========================================================

    if (
      url.pathname === "/api/verify" &&
      request.method === "POST"
    ) {

      try {

        const contentType =
          request.headers.get("content-type") || "";

        if (
          !contentType.includes("multipart/form-data")
        ) {

          return json({
            success: false,
            error:
              "Please upload PDF using multipart/form-data."
          }, 400);

        }

        // ----------------------------------------------------
        // FORM DATA
        // ----------------------------------------------------

        const formData =
          await request.formData();

        const file =
          formData.get("file");

        if (
          !file ||
          typeof file.arrayBuffer !== "function"
        ) {

          return json({
            success: false,
            error: "PDF file not found."
          }, 400);

        }

        // ----------------------------------------------------
        // FILE VALIDATION
        // ----------------------------------------------------

        const fileName =
          file.name || "uploaded.pdf";

        const isPDF =
          fileName.toLowerCase().endsWith(".pdf") ||
          file.type === "application/pdf";

        if (!isPDF) {

          return json({
            success: false,
            error: "Only PDF files are allowed."
          }, 400);

        }

        // ----------------------------------------------------
        // 20 MB LIMIT
        // ----------------------------------------------------

        const MAX_SIZE =
          20 * 1024 * 1024;

        if (file.size > MAX_SIZE) {

          return json({
            success: false,
            error: "PDF size must be below 20 MB."
          }, 413);

        }

        // ----------------------------------------------------
        // READ PDF
        // ----------------------------------------------------

        const buffer =
          await file.arrayBuffer();

        const bytes =
          new Uint8Array(buffer);

        // ----------------------------------------------------
        // PDF HEADER
        // ----------------------------------------------------

        const header =
          new TextDecoder()
            .decode(bytes.slice(0, 8));

        if (!header.startsWith("%PDF-")) {

          return json({
            success: false,
            error: "Uploaded file is not a valid PDF."
          }, 400);

        }

        // ----------------------------------------------------
        // LATIN-1 PDF TEXT
        // ----------------------------------------------------

        const pdfText =
          new TextDecoder("latin1")
            .decode(bytes);

        // ====================================================
        // SIGNATURE STRUCTURE
        // ====================================================

        const byteRangeMatch =
          pdfText.match(
            /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/
          );

        const hasByteRange =
          !!byteRangeMatch;

        const hasContents =
          /\/Contents\s*</.test(pdfText);

        const hasSignatureType =
          /\/Type\s*\/Sig\b/.test(pdfText);

        const hasPkcs7 =
          /\/SubFilter\s*\/adbe\.pkcs7\.detached\b/.test(pdfText) ||
          /\/SubFilter\s*\/adbe\.pkcs7\.sha1\b/.test(pdfText) ||
          /\/SubFilter\s*\/ETSI\.CAdES\.detached\b/.test(pdfText);

        const hasSignatureDictionary =
          /\/Sig\s*<<|\/Sig\s*\//.test(pdfText);

        const signatureDetected =
          hasByteRange ||
          hasContents ||
          hasSignatureType ||
          hasPkcs7 ||
          hasSignatureDictionary;

        // ====================================================
        // INITIAL RESULT
        // ====================================================

        const result = {

          success: true,

          file: {
            name: fileName,
            size: file.size,
            type:
              file.type ||
              "application/pdf"
          },

          pdf: {
            validHeader: true,
            signatureDetected
          },

          signatureStructure: {

            byteRange: hasByteRange,
            contents: hasContents,
            signatureType: hasSignatureType,
            pkcs7SubFilter: hasPkcs7,
            signatureDictionary:
              hasSignatureDictionary

          },

          verification: {

            status: "NOT_VERIFIED",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "Signature has not been cryptographically verified."

          }

        };

        // ====================================================
        // NO SIGNATURE
        // ====================================================

        if (!signatureDetected) {

          result.verification = {

            status: "NO_SIGNATURE",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "No PDF digital signature was detected."

          };

          return json(result);

        }

        // ====================================================
        // BYTE RANGE
        // ====================================================

        if (!byteRangeMatch) {

          result.verification = {

            status: "UNABLE_TO_VERIFY",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "Digital signature structure detected, but PDF ByteRange could not be parsed."

          };

          return json(result);

        }

        const byteRange =
          byteRangeMatch
            .slice(1)
            .map(Number);

        const [
          rangeStart1,
          rangeLength1,
          rangeStart2,
          rangeLength2
        ] = byteRange;

        const firstEnd =
          rangeStart1 +
          rangeLength1;

        const secondEnd =
          rangeStart2 +
          rangeLength2;

        const byteRangeValid =
          rangeStart1 === 0 &&
          rangeLength1 >= 0 &&
          rangeStart2 >= firstEnd &&
          rangeLength2 >= 0 &&
          firstEnd <= bytes.length &&
          secondEnd <= bytes.length;

        result.signatureStructure.byteRangeValues =
          byteRange;

        result.signatureStructure.byteRangeValid =
          byteRangeValid;

        if (!byteRangeValid) {

          result.verification = {

            status: "INVALID",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "PDF ByteRange is invalid or outside the uploaded file."

          };

          return json(result);

        }

        // ====================================================
        // SIGNED DATA
        // ====================================================

        const signedPart1 =
          bytes.slice(
            rangeStart1,
            rangeStart1 + rangeLength1
          );

        const signedPart2 =
          bytes.slice(
            rangeStart2,
            rangeStart2 + rangeLength2
          );

        const signedData =
          concatBytes(
            signedPart1,
            signedPart2
          );

        // ====================================================
        // EXTRACT CMS / PKCS#7
        // ====================================================

        const contentsHex =
          extractSignatureContents(
            pdfText,
            byteRangeMatch.index
          );

        if (!contentsHex) {

          result.verification = {

            status: "UNABLE_TO_VERIFY",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "PDF signature dictionary was found, but /Contents could not be extracted."

          };

          return json(result);

        }

        let cmsBytes;

        try {

          cmsBytes =
            hexToBytes(contentsHex);

        } catch {

          result.verification = {

            status: "UNABLE_TO_VERIFY",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "Unable to decode the PDF signature /Contents."

          };

          return json(result);

        }

        // ====================================================
        // ASN.1 / CMS PARSE
        // ====================================================

        let signedDataObject;

        try {

          const cmsParse =
            asn1js.fromBER(cmsBytes);

          if (
            cmsParse.offset === -1 ||
            !cmsParse.result
          ) {

            throw new Error(
              "ASN.1 CMS parsing failed."
            );

          }

          const cms =
            new pkijs.ContentInfo({
              schema: cmsParse.result
            });

          if (
            cms.contentType !==
            pkijs.ContentInfo.SIGNED_DATA
          ) {

            throw new Error(
              "Embedded signature is not CMS SignedData."
            );

          }

          signedDataObject =
            new pkijs.SignedData({
              schema: cms.content
            });

        } catch (error) {

          result.verification = {

            status: "UNABLE_TO_VERIFY",

            cryptographicVerification: false,

            documentIntegrity: false,

            certificatePresent: false,

            certificateChainVerified: false,

            certificateValidity: false,

            certificateStatus: "NOT_CHECKED",

            validFrom: null,

            validUntil: null,

            signer: null,

            issuer: null,

            serialNumber: null,

            message:
              "CMS/PKCS#7 signature could not be parsed: " +
              (
                error?.message ||
                "Unknown parsing error."
              )

          };

          return json(result);

        }

        // ====================================================
        // CERTIFICATES
        // ====================================================

        const certificates =
          Array.isArray(
            signedDataObject.certificates
          )
            ? signedDataObject.certificates
            : [];

        const signerCertificate =
          findSignerCertificate(
            signedDataObject
          );

        if (signerCertificate) {

          result.verification.certificatePresent =
            true;

          result.verification.signer =
            getCertificateSubject(
              signerCertificate
            );

          result.verification.issuer =
            getCertificateIssuer(
              signerCertificate
            );

          result.verification.serialNumber =
            safeCertificateSerial(
              signerCertificate
            );

          // ==================================================
          // CERTIFICATE VALIDITY
          // ==================================================

          const validity =
            getCertificateValidity(
              signerCertificate
            );

          result.verification.validFrom =
            validity.validFrom;

          result.verification.validUntil =
            validity.validUntil;

          result.verification.certificateStatus =
            validity.status;

          result.verification.certificateValidity =
            validity.valid;

        }

        result.verification.certificateCount =
          certificates.length;

        // ====================================================
        // CRYPTOGRAPHIC VERIFICATION
        // ====================================================

        try {

          const verifyResult =
            await signedDataObject.verify({

              signer: 0,

              data: signedData,

              checkChain: false

            });

          let signatureVerified =
            false;

          let signerCertificateVerified =
            false;

          let message =
            "Cryptographic verification failed.";

          if (
            typeof verifyResult ===
            "boolean"
          ) {

            signatureVerified =
              verifyResult;

          } else {

            signatureVerified =
              verifyResult
                ?.signatureVerified === true;

            signerCertificateVerified =
              verifyResult
                ?.signerCertificateVerified === true;

            message =
              verifyResult?.message ||
              (
                signatureVerified
                  ? "PDF digital signature is cryptographically valid."
                  : "PDF digital signature verification failed."
              );

          }

          result.verification
            .cryptographicVerification =
              signatureVerified;

          result.verification.documentIntegrity =
            signatureVerified;

          result.verification
            .certificateChainVerified =
              signerCertificateVerified;

          result.verification.verificationMessage =
            message;

          // ==================================================
          // FINAL STATUS
          // ==================================================

          if (signatureVerified) {

            result.verification.status =
              "CRYPTOGRAPHICALLY_VALID";

            result.verification.message =
              "Digital signature cryptographically verified against the exact PDF ByteRange.";

          } else {

            result.verification.status =
              "INVALID";

            result.verification.message =
              "Digital signature verification failed. The PDF content or signature may have been modified.";

          }

        } catch (error) {

          result.verification.status =
            "UNABLE_TO_VERIFY";

          result.verification
            .cryptographicVerification =
              false;

          result.verification.documentIntegrity =
            false;

          result.verification.message =
            "Cryptographic verification could not be completed: " +
            (
              error?.message ||
              "Unsupported signature or algorithm."
            );

        }

        return json(result);

      } catch (error) {

        return json({

          success: false,

          error:
            error?.message ||
            "Unable to process PDF."

        }, 500);

      }

    }

    // ========================================================
    // STATUS API
    // ========================================================

    if (
      url.pathname === "/api/status"
    ) {

      return json({

        success: true,

        service: "DSC Verifier API",

        status: "online",

        stage:
          "PDF structure + CMS/PKCS#7 cryptographic verification + certificate validity"

      });

    }

    // ========================================================
    // FRONTEND
    // ========================================================

    return new Response(
      FRONTEND_HTML,
      {
        headers: {
          "content-type":
            "text/html; charset=UTF-8",

          "cache-control":
            "no-store"
        }
      }
    );

  }

};


// ============================================================
// JSON
// ============================================================

function json(
  data,
  status = 200
) {

  return new Response(
    JSON.stringify(
      data,
      null,
      2
    ),
    {
      status,

      headers: {
        "content-type":
          "application/json; charset=UTF-8",

        "cache-control":
          "no-store"
      }
    }
  );

}


// ============================================================
// CONCAT BYTES
// ============================================================

function concatBytes(
  a,
  b
) {

  const output =
    new Uint8Array(
      a.length +
      b.length
    );

  output.set(a, 0);

  output.set(
    b,
    a.length
  );

  return output;

}


// ============================================================
// HEX -> BYTES
// ============================================================

function hexToBytes(
  hex
) {

  const clean =
    hex.replace(
      /[^0-9a-fA-F]/g,
      ""
    );

  if (!clean.length) {

    throw new Error(
      "Empty signature contents."
    );

  }

  if (
    clean.length % 2 !== 0
  ) {

    throw new Error(
      "Invalid hexadecimal signature."
    );

  }

  const bytes =
    new Uint8Array(
      clean.length / 2
    );

  for (
    let i = 0;
    i < clean.length;
    i += 2
  ) {

    bytes[i / 2] =
      parseInt(
        clean.slice(i, i + 2),
        16
      );

  }

  return bytes;

}


// ============================================================
// EXTRACT /CONTENTS
// ============================================================

function extractSignatureContents(
  pdfText,
  firstEnd,
  secondStart
) {

  try {

    // The PDF signature contents are located
    // inside the gap excluded by ByteRange.

    const signatureGap =
      pdfText.slice(
        firstEnd,
        secondStart
      );

    // Search ONLY inside the signature gap.
    // This avoids accidentally reading another
    // /Contents entry from the PDF.

    const match =
      signatureGap.match(
        /\/Contents\s*<([0-9A-Fa-f\s]+)>/
      );

    if (!match) {

      return null;

    }

    return match[1];

  } catch {

    return null;

  }

}

// ============================================================
// FIND SIGNER CERTIFICATE
// ============================================================

function findSignerCertificate(
  signedData
) {

  try {

    const certificates =
      Array.isArray(
        signedData.certificates
      )
        ? signedData.certificates
        : [];

    const signerInfos =
      Array.isArray(
        signedData.signerInfos
      )
        ? signedData.signerInfos
        : [];

    if (
      certificates.length === 0 ||
      signerInfos.length === 0
    ) {

      return null;

    }

    const signerInfo =
      signerInfos[0];

    const sid =
      signerInfo?.sid;

    if (!sid) {

      return null;

    }

    // --------------------------------------------------------
    // ISSUER + SERIAL MATCH
    // --------------------------------------------------------

    if (
      sid instanceof
      pkijs.IssuerAndSerialNumber
    ) {

      for (
        const item of certificates
      ) {

        if (
          !(item instanceof pkijs.Certificate)
        ) {

          continue;

        }

        const serialMatches =
          compareArrayBuffers(
            item.serialNumber
              ?.valueBlock
              ?.valueHex,

            sid.serialNumber
              ?.valueBlock
              ?.valueHex
          );

        if (!serialMatches) {

          continue;

        }

        try {

          if (
            item.issuer?.isEqual(
              sid.issuer
            )
          ) {

            return item;

          }

        } catch {

          // Continue fallback

        }

      }

    }

    // --------------------------------------------------------
    // FALLBACK - FIRST X509 CERTIFICATE
    // --------------------------------------------------------

    for (
      const item of certificates
    ) {

      if (
        item instanceof
        pkijs.Certificate
      ) {

        return item;

      }

    }

    return null;

  } catch {

    return null;

  }

}


// ============================================================
// COMPARE ARRAY BUFFERS
// ============================================================

function compareArrayBuffers(
  a,
  b
) {

  if (!a || !b) {

    return false;

  }

  const aa =
    new Uint8Array(a);

  const bb =
    new Uint8Array(b);

  if (
    aa.length !==
    bb.length
  ) {

    return false;

  }

  for (
    let i = 0;
    i < aa.length;
    i++
  ) {

    if (
      aa[i] !==
      bb[i]
    ) {

      return false;

    }

  }

  return true;

}


// ============================================================
// CERTIFICATE SUBJECT
// ============================================================

function getCertificateSubject(
  cert
) {

  try {

    const values =
      cert?.subject
        ?.typesAndValues ||
      [];

    const result =
      values
        .map(item =>
          getNameValue(item)
        )
        .filter(Boolean)
        .join(", ");

    return result ||
      "Certificate subject available";

  } catch {

    return "Certificate subject unavailable";

  }

}


// ============================================================
// CERTIFICATE ISSUER
// ============================================================

function getCertificateIssuer(
  cert
) {

  try {

    const values =
      cert?.issuer
        ?.typesAndValues ||
      [];

    const result =
      values
        .map(item =>
          getNameValue(item)
        )
        .filter(Boolean)
        .join(", ");

    return result ||
      "Certificate issuer available";

  } catch {

    return "Certificate issuer unavailable";

  }

}


// ============================================================
// NAME VALUE
// ============================================================

function getNameValue(
  item
) {

  try {

    const value =
      item?.value
        ?.valueBlock
        ?.value;

    if (
      typeof value ===
      "string"
    ) {

      return value;

    }

    if (
      value !== undefined &&
      value !== null
    ) {

      return String(value);

    }

    return "";

  } catch {

    return "";

  }

}


// ============================================================
// CERTIFICATE SERIAL
// ============================================================

function safeCertificateSerial(
  cert
) {

  try {

    const valueHex =
      cert
        ?.serialNumber
        ?.valueBlock
        ?.valueHex;

    if (!valueHex) {

      return null;

    }

    return bytesToHex(
      new Uint8Array(
        valueHex
      )
    );

  } catch {

    return null;

  }

}


// ============================================================
// CERTIFICATE VALIDITY
// ============================================================

function getCertificateValidity(
  cert
) {

  try {

    const notBefore =
      cert?.notBefore?.value;

    const notAfter =
      cert?.notAfter?.value;

    if (
      !notBefore ||
      !notAfter
    ) {

      return {

        valid: false,

        status: "NOT_AVAILABLE",

        validFrom: null,

        validUntil: null

      };

    }

    const now =
      new Date();

    const from =
      new Date(notBefore);

    const until =
      new Date(notAfter);

    let status =
      "VALID";

    let valid =
      true;

    if (
      now < from
    ) {

      status =
        "NOT_YET_VALID";

      valid =
        false;

    }

    else if (
      now > until
    ) {

      status =
        "EXPIRED";

      valid =
        false;

    }

    return {

      valid,

      status,

      validFrom:
        formatDateTime(from),

      validUntil:
        formatDateTime(until)

    };

  } catch {

    return {

      valid: false,

      status: "NOT_AVAILABLE",

      validFrom: null,

      validUntil: null

    };

  }

}


// ============================================================
// FORMAT DATE
// ============================================================

function formatDateTime(
  date
) {

  try {

    if (
      !(date instanceof Date) ||
      Number.isNaN(
        date.getTime()
      )
    ) {

      return null;

    }

    return date.toISOString();

  } catch {

    return null;

  }

}


// ============================================================
// BYTES -> HEX
// ============================================================

function bytesToHex(
  bytes
) {

  return Array
    .from(bytes)
    .map(
      b =>
        b
          .toString(16)
          .padStart(2, "0")
    )
    .join("");

}


// ============================================================
// FRONTEND
// ============================================================

const FRONTEND_HTML = `<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1.0"
>

<title>DSC Verifier</title>

<style>

*{
  box-sizing:border-box;
}

body{
  margin:0;
  min-height:100vh;

  font-family:
    Arial,
    Helvetica,
    sans-serif;

  color:#fff;

  background:
    radial-gradient(
      circle at 10% 10%,
      #183a91 0%,
      transparent 35%
    ),

    radial-gradient(
      circle at 90% 90%,
      #006d66 0%,
      transparent 35%
    ),

    #06101f;
}

.container{
  width:min(1050px,94%);
  margin:auto;

  padding:
    55px 0
    35px;
}

.header{
  text-align:center;
  margin-bottom:35px;
}

.logo{
  width:76px;
  height:76px;

  margin:auto;

  border-radius:22px;

  display:flex;
  align-items:center;
  justify-content:center;

  font-size:42px;

  background:
    linear-gradient(
      135deg,
      #247cff,
      #13c6b5
    );

  box-shadow:
    0 15px 40px
    rgba(0,0,0,.35);
}

h1{
  margin:
    20px 0
    8px;

  font-size:52px;
}

.subtitle{
  color:#a9c7e8;
  font-size:18px;
}

.card{
  padding:25px;

  border-radius:26px;

  background:
    rgba(255,255,255,.08);

  border:
    1px solid
    rgba(255,255,255,.16);

  backdrop-filter:
    blur(12px);

  box-shadow:
    0 25px 70px
    rgba(0,0,0,.3);
}

.drop{
  min-height:330px;

  border:
    2px dashed
    rgba(180,210,245,.45);

  border-radius:22px;

  display:flex;

  align-items:center;
  justify-content:center;

  text-align:center;

  padding:30px;

  cursor:pointer;

  transition:.2s;
}

.drop:hover{
  border-color:#25bfff;

  background:
    rgba(30,120,220,.08);
}

.drop.dragover{
  border-color:#13c6b5;

  background:
    rgba(19,198,181,.12);
}

.icon{
  font-size:60px;
}

.drop h2{
  margin:
    15px 0
    8px;
}

.drop p{
  color:#aebed2;
}

input[type="file"]{
  display:none;
}

.choose-btn,
button{
  border:0;

  padding:
    15px 28px;

  border-radius:12px;

  color:#fff;

  font-size:16px;

  font-weight:bold;

  cursor:pointer;

  background:
    linear-gradient(
      90deg,
      #187cff,
      #13c6b5
    );

  transition:.2s;
}

.choose-btn{
  display:inline-flex;

  align-items:center;
  justify-content:center;
}

.choose-btn:hover,
button:hover:not(:disabled){
  transform:
    translateY(-2px);

  box-shadow:
    0 10px 25px
    rgba(24,124,255,.25);
}

button:disabled{
  opacity:.5;
  cursor:not-allowed;
}

.file{
  margin-top:20px;

  padding:15px;

  border-radius:12px;

  background:
    rgba(0,0,0,.25);

  display:none;

  word-break:break-word;
}

.verify{
  text-align:center;

  margin-top:20px;

  display:none;
}

.result{
  display:none;
  margin-top:25px;
}

.status{
  padding:18px;

  border-radius:15px;

  font-size:21px;

  font-weight:bold;

  text-align:center;

  margin-bottom:18px;
}

.valid{
  background:
    rgba(0,190,120,.14);

  border:
    1px solid
    #19c98b;

  color:#42e8aa;
}

.notdetected,
.invalid{
  background:
    rgba(255,70,70,.12);

  border:
    1px solid
    #c94b4b;

  color:#ff7777;
}

.unable{
  background:
    rgba(255,174,0,.12);

  border:
    1px solid
    #c99020;

  color:#ffc238;
}

.cert-valid{
  color:#42e8aa;
}

.cert-expired{
  color:#ff7777;
}

.cert-future{
  color:#ffc238;
}

.grid{
  display:grid;

  grid-template-columns:
    1fr 1fr;

  gap:15px;
}

.box{
  padding:18px;

  border-radius:15px;

  background:
    rgba(0,0,0,.2);
}

.label{
  color:#91a8c2;

  font-size:13px;

  margin-bottom:6px;
}

.value{
  font-size:17px;

  font-weight:bold;

  word-break:break-word;

  line-height:1.5;
}

.note{
  margin-top:18px;

  padding:16px;

  border-radius:14px;

  color:#a9c8e8;

  background:
    rgba(30,120,220,.10);

  border:
    1px solid
    rgba(80,160,240,.2);

  line-height:1.6;
}

.footer{
  text-align:center;

  color:#6e87a4;

  margin-top:30px;

  font-size:14px;
}

@media(max-width:650px){

  .container{
    width:94%;

    padding:
      30px 0
      25px;
  }

  h1{
    font-size:38px;
  }

  .subtitle{
    font-size:15px;
  }

  .card{
    padding:15px;
    border-radius:20px;
  }

  .drop{
    min-height:300px;
    padding:20px;
  }

  .drop h2{
    font-size:22px;
  }

  .grid{
    grid-template-columns:
      1fr;
  }

  .status{
    font-size:17px;
  }

}

</style>

</head>

<body>

<div class="container">

<div class="header">

<div class="logo">
🔐
</div>

<h1>
DSC Verifier
</h1>

<div class="subtitle">
Digital Signature Certificate Verification Tool
</div>

</div>

<div class="card">

<div
  id="drop"
  class="drop"
>

<div>

<div class="icon">
📄
</div>

<h2>
Upload Digitally Signed PDF
</h2>

<p>
Select or drag & drop your digitally signed certificate PDF
</p>

<br>

<button
  type="button"
  id="chooseBtn"
  class="choose-btn"
>
📁 Choose PDF
</button>

</div>

</div>

<input
  id="pdf"
  type="file"
  accept=".pdf,application/pdf"
>

<div
  id="fileBox"
  class="file"
></div>

<div
  id="errorBox"
  class="error"
></div>

<div
  id="verifyBox"
  class="verify"
>

<button
  id="verifyBtn"
  type="button"
>
🔍 Verify PDF
</button>

</div>

<div
  id="result"
  class="result"
>

<div
  id="status"
  class="status"
></div>

<div class="grid">

<div class="box">
<div class="label">FILE NAME</div>
<div id="fileName" class="value">-</div>
</div>

<div class="box">
<div class="label">FILE SIZE</div>
<div id="fileSize" class="value">-</div>
</div>

<div class="box">
<div class="label">PDF</div>
<div id="pdfValid" class="value">-</div>
</div>

<div class="box">
<div class="label">BYTE RANGE</div>
<div id="byteRange" class="value">-</div>
</div>

<div class="box">
<div class="label">SIGNATURE CONTENTS</div>
<div id="contents" class="value">-</div>
</div>

<div class="box">
<div class="label">SIGNATURE TYPE</div>
<div id="sigType" class="value">-</div>
</div>

<div class="box">
<div class="label">PKCS#7 / CAdES</div>
<div id="pkcs7" class="value">-</div>
</div>

<div class="box">
<div class="label">SIGNATURE DICTIONARY</div>
<div id="sigDictionary" class="value">-</div>
</div>

<div class="box">
<div class="label">CRYPTOGRAPHIC VERIFICATION</div>
<div id="cryptoStatus" class="value">-</div>
</div>

<div class="box">
<div class="label">DOCUMENT INTEGRITY</div>
<div id="integrity" class="value">-</div>
</div>

<div class="box">
<div class="label">SIGNER CERTIFICATE</div>
<div id="certificate" class="value">-</div>
</div>

<div class="box">
<div class="label">CERTIFICATE STATUS</div>
<div id="certStatus" class="value">-</div>
</div>

<div class="box">
<div class="label">VALID FROM</div>
<div id="validFrom" class="value">-</div>
</div>

<div class="box">
<div class="label">VALID UNTIL</div>
<div id="validUntil" class="value">-</div>
</div>

<div class="box">
<div class="label">SIGNER</div>
<div id="signer" class="value">-</div>
</div>

<div class="box">
<div class="label">ISSUER</div>
<div id="issuer" class="value">-</div>
</div>

<div class="box">
<div class="label">SERIAL NUMBER</div>
<div id="serial" class="value">-</div>
</div>

<div class="box">
<div class="label">CERTIFICATE CHAIN</div>
<div id="chain" class="value">-</div>
</div>

</div>

<div class="note">

⚠️ <b>Verification information:</b>

<br><br>

The tool performs cryptographic CMS/PKCS#7
verification against the exact PDF ByteRange.

<br><br>

Certificate validity is checked separately using
the certificate's Valid From and Valid Until dates.

<br><br>

Certificate chain trust is reported separately.
A cryptographically valid signature does not by itself
mean that the certificate is trusted by a particular
government or root authority.

</div>

</div>

</div>

<div class="footer">

DSC Verifier • Independent verification tool
• Not a government website

</div>

</div>

<script>

const input =
  document.getElementById("pdf");

const drop =
  document.getElementById("drop");

const chooseBtn =
  document.getElementById("chooseBtn");

const fileBox =
  document.getElementById("fileBox");

const errorBox =
  document.getElementById("errorBox");

const verifyBox =
  document.getElementById("verifyBox");

const verifyBtn =
  document.getElementById("verifyBtn");

const result =
  document.getElementById("result");

let selectedFile = null;


// ============================================================
// FILE PICKER
// ============================================================

chooseBtn.addEventListener(
  "click",
  function(event){

    event.preventDefault();

    event.stopPropagation();

    input.click();

  }
);


drop.addEventListener(
  "click",
  function(event){

    if (
      event.target ===
      chooseBtn
    ) {

      return;

    }

    input.click();

  }
);


input.addEventListener(
  "change",
  function(){

    if (
      !input.files.length
    ) {

      return;

    }

    handleFile(
      input.files[0]
    );

  }
);


// ============================================================
// DRAG & DROP
// ============================================================

drop.addEventListener(
  "dragover",
  function(event){

    event.preventDefault();

    drop.classList.add(
      "dragover"
    );

  }
);


drop.addEventListener(
  "dragleave",
  function(){

    drop.classList.remove(
      "dragover"
    );

  }
);


drop.addEventListener(
  "drop",
  function(event){

    event.preventDefault();

    drop.classList.remove(
      "dragover"
    );

    const files =
      event.dataTransfer.files;

    if (
      !files ||
      !files.length
    ) {

      return;

    }

    handleFile(
      files[0]
    );

  }
);


// ============================================================
// HANDLE FILE
// ============================================================

function handleFile(file){

  clearError();

  result.style.display =
    "none";

  verifyBox.style.display =
    "none";

  fileBox.style.display =
    "none";

  const isPDF =
    file.type ===
      "application/pdf" ||
    file.name
      .toLowerCase()
      .endsWith(".pdf");

  if (!isPDF) {

    showError(
      "❌ Please select a valid PDF file."
    );

    input.value = "";

    return;

  }

  const MAX_SIZE =
    20 * 1024 * 1024;

  if (
    file.size >
    MAX_SIZE
  ) {

    showError(
      "❌ PDF size must be below 20 MB."
    );

    input.value = "";

    return;

  }

  selectedFile =
    file;

  fileBox.style.display =
    "block";

  fileBox.textContent =
    "📄 Selected: " +
    file.name +
    " • " +
    formatBytes(
      file.size
    );

  verifyBox.style.display =
    "block";

}


// ============================================================
// VERIFY
// ============================================================

verifyBtn.addEventListener(
  "click",
  async function(){

    if (!selectedFile) {

      showError(
        "Please select a PDF first."
      );

      return;

    }

    clearError();

    verifyBtn.disabled =
      true;

    verifyBtn.textContent =
      "⏳ Cryptographically Verifying...";

    const formData =
      new FormData();

    formData.append(
      "file",
      selectedFile
    );

    try {

      const response =
        await fetch(
          "/api/verify",
          {
            method: "POST",
            body: formData
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.success
      ) {

        throw new Error(
          data.error ||
          "Verification failed."
        );

      }

      result.style.display =
        "block";

      // ------------------------------------------------------
      // BASIC INFORMATION
      // ------------------------------------------------------

      setText(
        "fileName",
        data.file.name
      );

      setText(
        "fileSize",
        formatBytes(
          data.file.size
        )
      );

      setText(
        "pdfValid",
        data.pdf.validHeader
          ? "✓ Valid PDF"
          : "✗ Invalid PDF"
      );

      setText(
        "byteRange",
        data.signatureStructure.byteRangeValid
          ? "✓ Valid"
          : "✗ Invalid"
      );

      setText(
        "contents",
        data.signatureStructure.contents
          ? "✓ Found"
          : "✗ Not Found"
      );

      setText(
        "sigType",
        data.signatureStructure.signatureType
          ? "✓ Found"
          : "✗ Not Found"
      );

      setText(
        "pkcs7",
        data.signatureStructure.pkcs7SubFilter
          ? "✓ Found"
          : "✗ Not Found"
      );

      setText(
        "sigDictionary",
        data.signatureStructure.signatureDictionary
          ? "✓ Found"
          : "✗ Not Found"
      );

      // ------------------------------------------------------
      // CRYPTO
      // ------------------------------------------------------

      setText(
        "cryptoStatus",
        data.verification
          .cryptographicVerification
          ? "✓ VALID"
          : "✗ NOT VERIFIED"
      );

      setText(
        "integrity",
        data.verification
          .documentIntegrity
          ? "✓ INTACT"
          : "✗ NOT VERIFIED"
      );

      setText(
        "certificate",
        data.verification
          .certificatePresent
          ? "✓ Found"
          : "✗ Not Found"
      );

      // ------------------------------------------------------
      // CERTIFICATE VALIDITY
      // ------------------------------------------------------

      const certStatus =
        data.verification
          .certificateStatus;

      const certElement =
        document.getElementById(
          "certStatus"
        );

      certElement.className =
        "value";

      if (
        certStatus ===
        "VALID"
      ) {

        certElement.classList.add(
          "cert-valid"
        );

        certElement.textContent =
          "✓ VALID";

      }

      else if (
        certStatus ===
        "EXPIRED"
      ) {

        certElement.classList.add(
          "cert-expired"
        );

        certElement.textContent =
          "✗ EXPIRED";

      }

      else if (
        certStatus ===
        "NOT_YET_VALID"
      ) {

        certElement.classList.add(
          "cert-future"
        );

        certElement.textContent =
          "⚠ NOT YET VALID";

      }

      else {

        certElement.textContent =
          "Not Available";

      }

      setText(
        "validFrom",
        formatCertificateDate(
          data.verification.validFrom
        )
      );

      setText(
        "validUntil",
        formatCertificateDate(
          data.verification.validUntil
        )
      );

      // ------------------------------------------------------
      // SIGNER INFORMATION
      // ------------------------------------------------------

      setText(
        "signer",
        cleanCertificateText(
          data.verification.signer
        )
      );

      setText(
        "issuer",
        cleanCertificateText(
          data.verification.issuer
        )
      );

      setText(
        "serial",
        data.verification.serialNumber ||
        "-"
      );

      setText(
        "chain",
        data.verification
          .certificateChainVerified
          ? "✓ Verified"
          : "Not checked"
      );

      // ------------------------------------------------------
      // MAIN STATUS
      // ------------------------------------------------------

      const status =
        document.getElementById(
          "status"
        );

      const verificationStatus =
        data.verification.status;

      if (
        verificationStatus ===
        "CRYPTOGRAPHICALLY_VALID"
      ) {

        status.className =
          "status valid";

        status.textContent =
          "✅ DIGITAL SIGNATURE CRYPTOGRAPHICALLY VALID";

      }

      else if (
        verificationStatus ===
        "INVALID"
      ) {

        status.className =
          "status invalid";

        status.textContent =
          "❌ DIGITAL SIGNATURE INVALID";

      }

      else if (
        verificationStatus ===
        "NO_SIGNATURE"
      ) {

        status.className =
          "status notdetected";

        status.textContent =
          "❌ DIGITAL SIGNATURE NOT DETECTED";

      }

      else {

        status.className =
          "status unable";

        status.textContent =
          "⚠️ SIGNATURE DETECTED — UNABLE TO VERIFY";

      }

      result.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });

    }

    catch(error) {

      showError(
        "❌ " +
        (
          error.message ||
          "Unable to connect to verification server."
        )
      );

    }

    finally {

      verifyBtn.disabled =
        false;

      verifyBtn.textContent =
        "🔍 Verify PDF";

    }

  }
);


// ============================================================
// SET TEXT
// ============================================================

function setText(
  id,
  value
){

  const element =
    document.getElementById(id);

  if (element) {

    element.textContent =
      value || "-";

  }

}


// ============================================================
// CLEAN CERTIFICATE TEXT
// ============================================================

function cleanCertificateText(
  value
){

  if (
    !value ||
    value === "-"
  ) {

    return "-";

  }

  return String(value)
    .replace(
      /,\s*/g,
      ", "
    )
    .replace(
      /\s+/g,
      " "
    )
    .trim();

}


// ============================================================
// DATE FORMAT
// ============================================================

function formatCertificateDate(
  value
){

  if (!value) {

    return "-";

  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {

    return value;

  }

  return date.toLocaleString(
    "en-IN",
    {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    }
  );

}


// ============================================================
// BYTES
// ============================================================

function formatBytes(
  bytes
){

  if (
    bytes === 0
  ) {

    return "0 Bytes";

  }

  const units = [
    "Bytes",
    "KB",
    "MB",
    "GB"
  ];

  const i =
    Math.floor(
      Math.log(bytes) /
      Math.log(1024)
    );

  return (
    parseFloat(
      (
        bytes /
        Math.pow(
          1024,
          i
        )
      ).toFixed(2)
    ) +
    " " +
    units[i]
  );

}


// ============================================================
// ERROR
// ============================================================

function showError(
  message
){

  errorBox.style.display =
    "block";

  errorBox.textContent =
    message;

}


function clearError(){

  errorBox.style.display =
    "none";

  errorBox.textContent =
    "";

}

</script>

</body>

</html>`;
