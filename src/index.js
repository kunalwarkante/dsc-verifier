import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

/* ============================================================
   PKI.JS CRYPTO ENGINE
   Cloudflare Workers WebCrypto
   ============================================================ */

const cryptoEngine = new pkijs.CryptoEngine({
  name: "CloudflareWebCrypto",
  crypto: crypto,
  subtle: crypto.subtle
});

pkijs.setEngine(
  "CloudflareWebCrypto",
  cryptoEngine
);


/* ============================================================
   WORKER
   ============================================================ */

export default {

  async fetch(request) {

    const url = new URL(request.url);

    /* ========================================================
       CORS / OPTIONS
       ======================================================== */

    if (request.method === "OPTIONS") {

      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });

    }


    /* ========================================================
       STATUS API
       ======================================================== */

    if (
      url.pathname === "/api/status" &&
      request.method === "GET"
    ) {

      return json({
        success: true,
        service: "DSC Verifier API",
        status: "online",
        version: "2.0",
        engine: "PKI.js + Cloudflare WebCrypto",
        verification:
          "PDF ByteRange + CMS/PKCS#7 cryptographic verification"
      });

    }


    /* ========================================================
       PDF VERIFY API
       ======================================================== */

    if (
      url.pathname === "/api/verify" &&
      request.method === "POST"
    ) {

      try {

        const contentType =
          request.headers.get("content-type") || "";


        /* ----------------------------------------------------
           Multipart validation
           ---------------------------------------------------- */

        if (
          !contentType.toLowerCase().includes(
            "multipart/form-data"
          )
        ) {

          return json(
            {
              success: false,
              error:
                "Please upload PDF using multipart/form-data."
            },
            400
          );

        }


        /* ----------------------------------------------------
           Form data
           ---------------------------------------------------- */

        const formData =
          await request.formData();


        const file =
          formData.get("file");


        if (
          !file ||
          typeof file.arrayBuffer !== "function"
        ) {

          return json(
            {
              success: false,
              error:
                "PDF file not found."
            },
            400
          );

        }


        /* ----------------------------------------------------
           File information
           ---------------------------------------------------- */

        const fileName =
          typeof file.name === "string" &&
          file.name.length
            ? file.name
            : "uploaded.pdf";


        const fileSize =
          Number(file.size || 0);


        const fileType =
          file.type ||
          "application/pdf";


        /* ----------------------------------------------------
           PDF validation
           ---------------------------------------------------- */

        const isPDF =
          fileName
            .toLowerCase()
            .endsWith(".pdf") ||
          fileType
            .toLowerCase()
            .includes("application/pdf");


        if (!isPDF) {

          return json(
            {
              success: false,
              error:
                "Only PDF files are allowed."
            },
            400
          );

        }


        /* ----------------------------------------------------
           20 MB limit
           ---------------------------------------------------- */

        const MAX_SIZE =
          20 * 1024 * 1024;


        if (fileSize > MAX_SIZE) {

          return json(
            {
              success: false,
              error:
                "PDF size must be below 20 MB."
            },
            413
          );

        }


        /* ----------------------------------------------------
           Read file
           ---------------------------------------------------- */

        const buffer =
          await file.arrayBuffer();


        const bytes =
          new Uint8Array(buffer);


        if (bytes.length < 8) {

          return json(
            {
              success: false,
              error:
                "Uploaded file is too small to be a PDF."
            },
            400
          );

        }


        /* ----------------------------------------------------
           PDF header
           ---------------------------------------------------- */

        const header =
          new TextDecoder()
            .decode(
              bytes.slice(0, 8)
            );


        if (
          !header.startsWith("%PDF-")
        ) {

          return json(
            {
              success: false,
              error:
                "Uploaded file is not a valid PDF."
            },
            400
          );

        }


        /* ====================================================
           PDF TEXT
           ==================================================== */

        const pdfText =
          new TextDecoder("latin1")
            .decode(bytes);


        /* ====================================================
           SIGNATURE STRUCTURE DETECTION
           ==================================================== */

        const byteRangeMatches =
          Array.from(
            pdfText.matchAll(
              /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g
            )
          );


        const hasByteRange =
          byteRangeMatches.length > 0;


        const hasContents =
          /\/Contents\s*</i.test(
            pdfText
          );


        const hasSignatureType =
          /\/Type\s*\/Sig\b/i.test(
            pdfText
          );


        const hasPkcs7 =
          /\/SubFilter\s*\/adbe\.pkcs7\.detached\b/i.test(
            pdfText
          ) ||
          /\/SubFilter\s*\/adbe\.pkcs7\.sha1\b/i.test(
            pdfText
          ) ||
          /\/SubFilter\s*\/ETSI\.CAdES\.detached\b/i.test(
            pdfText
          );


        const hasSignatureDictionary =
          /\/Sig\s*<</i.test(
            pdfText
          ) ||
          /\/Sig\s*\//i.test(
            pdfText
          );


        const signatureDetected =
          hasByteRange ||
          hasContents ||
          hasSignatureType ||
          hasPkcs7 ||
          hasSignatureDictionary;


        /* ====================================================
           INITIAL RESULT
           ==================================================== */

        const result = {

          success: true,

          file: {
            name: fileName,
            size: fileSize,
            type: fileType
          },

          pdf: {
            validHeader: true,
            signatureDetected:
              signatureDetected
          },

          signatureStructure: {

            byteRange:
              hasByteRange,

            byteRangeCount:
              byteRangeMatches.length,

            contents:
              hasContents,

            signatureType:
              hasSignatureType,

            pkcs7SubFilter:
              hasPkcs7,

            signatureDictionary:
              hasSignatureDictionary

          },

          verification: {

            status:
              "NOT_VERIFIED",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "Signature has not been cryptographically verified."

          }

        };


        /* ====================================================
           NO SIGNATURE
           ==================================================== */

        if (!signatureDetected) {

          result.verification = {

            status:
              "NO_SIGNATURE",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "No PDF digital signature was detected."

          };


          return json(result);

        }


        /* ====================================================
           BYTE RANGE REQUIRED
           ==================================================== */

        if (!hasByteRange) {

          result.verification = {

            status:
              "UNABLE_TO_VERIFY",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "Digital signature structure detected, but PDF ByteRange could not be parsed."

          };


          return json(result);

        }


        /* ====================================================
           USE FIRST PDF SIGNATURE
           ==================================================== */

        const byteRangeMatch =
          byteRangeMatches[0];


        const byteRange =
          byteRangeMatch
            .slice(1)
            .map(Number);


        const byteRangePosition =
          byteRangeMatch.index;


        const [
          rangeStart1,
          rangeLength1,
          rangeStart2,
          rangeLength2
        ] =
          byteRange;


        /* ====================================================
           BYTE RANGE VALIDATION
           ==================================================== */

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
          secondEnd <= bytes.length &&
          rangeStart2 >= 0;


        result.signatureStructure.byteRangeValues =
          byteRange;


        result.signatureStructure.byteRangeValid =
          byteRangeValid;


        if (!byteRangeValid) {

          result.verification = {

            status:
              "INVALID",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "PDF ByteRange is invalid or outside the uploaded file."

          };


          return json(result);

        }


        /* ====================================================
           SIGNED DATA
           ==================================================== */

        const signedPart1 =
          bytes.slice(
            rangeStart1,
            firstEnd
          );


        const signedPart2 =
          bytes.slice(
            rangeStart2,
            secondEnd
          );


        const signedData =
          concatBytes(
            signedPart1,
            signedPart2
          );


        /* ====================================================
           EXTRACT SIGNATURE CONTENTS
           ==================================================== */

        const contentsHex =
          extractSignatureContents(
            pdfText,
            byteRangePosition
          );


        if (!contentsHex) {

          result.verification = {

            status:
              "UNABLE_TO_VERIFY",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "PDF signature dictionary was found, but /Contents could not be extracted."

          };


          return json(result);

        }


        /* ====================================================
           HEX -> BYTES
           ==================================================== */

        let cmsBytes;


        try {

          cmsBytes =
            hexToBytes(
              contentsHex
            );

        } catch (error) {

          result.verification = {

            status:
              "UNABLE_TO_VERIFY",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "Unable to decode PDF signature /Contents: " +
              getErrorMessage(error)

          };


          return json(result);

        }


        /* ====================================================
           CMS PARSING
           ==================================================== */

        let signedDataObject;


        try {

          const cmsParse =
            asn1js.fromBER(
              cmsBytes
            );


          if (
            cmsParse.offset === -1 ||
            !cmsParse.result
          ) {

            throw new Error(
              "ASN.1 BER parsing failed."
            );

          }


          /*
             PDF signature /Contents normally contains
             a DER encoded CMS object followed by zero
             padding. We only use the actual DER object.
          */

          const cmsDER =
            cmsBytes.slice(
              0,
              cmsParse.offset
            );


          const cms =
            pkijs.ContentInfo.fromBER(
              cmsDER
            );


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
              schema:
                cms.content
            });


        } catch (error) {

          result.verification = {

            status:
              "UNABLE_TO_VERIFY",

            cryptographicVerification:
              false,

            documentIntegrity:
              false,

            certificatePresent:
              false,

            certificateChainVerified:
              false,

            certificateCount:
              0,

            signerCount:
              0,

            signer:
              null,

            issuer:
              null,

            serialNumber:
              null,

            message:
              "CMS/PKCS#7 signature could not be parsed: " +
              getErrorMessage(error)

          };


          return json(result);

        }


        /* ====================================================
           CERTIFICATES
           ==================================================== */

        const allCertificates =
          Array.isArray(
            signedDataObject.certificates
          )
            ? signedDataObject.certificates
            : [];


        const certificates =
          allCertificates.filter(
            item =>
              item instanceof
              pkijs.Certificate
          );


        const signerInfos =
          Array.isArray(
            signedDataObject.signerInfos
          )
            ? signedDataObject.signerInfos
            : [];


        result.verification.certificateCount =
          certificates.length;


        result.verification.signerCount =
          signerInfos.length;


        /* ====================================================
           FIND SIGNER CERTIFICATE
           ==================================================== */

        let signerIndex = 0;

        let signerCertificate =
          null;


        for (
          let i = 0;
          i < signerInfos.length;
          i++
        ) {

          const found =
            findCertificateForSigner(
              signerInfos[i],
              certificates
            );


          if (found) {

            signerIndex =
              i;

            signerCertificate =
              found;

            break;

          }

        }


        /*
           Fallback: if exact SID matching is not possible,
           use first X.509 certificate.
        */

        if (!signerCertificate) {

          signerCertificate =
            certificates[0] ||
            null;

          signerIndex =
            0;

        }


        /* ====================================================
           CERTIFICATE INFORMATION
           ==================================================== */

        if (signerCertificate) {

          result.verification
            .certificatePresent =
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

        }


        /* ====================================================
           CRYPTOGRAPHIC VERIFICATION
           ==================================================== */

        try {

          if (
            signerInfos.length === 0
          ) {

            throw new Error(
              "CMS contains no SignerInfo."
            );

          }


          /*
             PKI.js verifies the CMS signature against
             the supplied detached PDF ByteRange data.
          */

          const verifyResult =
            await signedDataObject.verify({

              signer:
                signerIndex,

              data:
                signedData,

              checkChain:
                false

            });


          let signatureVerified =
            false;


          let signerCertificateVerified =
            false;


          let verificationMessage =
            "Cryptographic verification failed.";


          if (
            typeof verifyResult ===
            "boolean"
          ) {

            signatureVerified =
              verifyResult;

            verificationMessage =
              verifyResult
                ? "Digital signature is cryptographically valid."
                : "Digital signature verification failed.";

          } else {

            signatureVerified =
              verifyResult
                ?.signatureVerified === true;


            signerCertificateVerified =
              verifyResult
                ?.signerCertificateVerified === true;


            verificationMessage =
              verifyResult?.message ||
              (
                signatureVerified
                  ? "Digital signature is cryptographically valid."
                  : "Digital signature verification failed."
              );


            /*
               If PKI.js returned a signer certificate,
               prefer it over our manually detected one.
            */

            if (
              verifyResult?.signerCertificate
            ) {

              signerCertificate =
                verifyResult.signerCertificate;


              result.verification
                .certificatePresent =
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

            }

          }


          result.verification
            .cryptographicVerification =
              signatureVerified;


          /*
             If the CMS signature verifies against the
             exact PDF ByteRange, the signed bytes have
             not been altered.
          */

          result.verification
            .documentIntegrity =
              signatureVerified;


          result.verification
            .certificateChainVerified =
              signerCertificateVerified;


          result.verification
            .verificationMessage =
              verificationMessage;


          if (signatureVerified) {

            result.verification.status =
              "CRYPTOGRAPHICALLY_VALID";


            result.verification.message =
              "Digital signature cryptographically verified against the exact PDF ByteRange.";

          } else {

            result.verification.status =
              "INVALID";


            result.verification.message =
              "Digital signature verification failed. The signed PDF data or signature is not valid.";

          }


        } catch (error) {

          result.verification.status =
            "UNABLE_TO_VERIFY";


          result.verification
            .cryptographicVerification =
              false;


          result.verification
            .documentIntegrity =
              false;


          result.verification.message =
            "Cryptographic verification could not be completed: " +
            getErrorMessage(error);

        }


        /* ====================================================
           RETURN
           ==================================================== */

        return json(result);

      } catch (error) {

        return json(
          {
            success: false,
            error:
              getErrorMessage(error) ||
              "Unable to process PDF."
          },
          500
        );

      }

    }


    /* ========================================================
       FRONTEND
       ======================================================== */

    return new Response(
      FRONTEND_HTML,
      {
        headers: {
          "content-type":
            "text/html; charset=UTF-8",

          "cache-control":
            "no-store",

          "Access-Control-Allow-Origin":
            "*"
        }
      }
    );

  }

};


/* ============================================================
   JSON RESPONSE
   ============================================================ */

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
          "no-store",

        "Access-Control-Allow-Origin":
          "*"
      }
    }
  );

}


/* ============================================================
   ERROR MESSAGE
   ============================================================ */

function getErrorMessage(
  error
) {

  if (
    error &&
    typeof error.message === "string"
  ) {

    return error.message;

  }

  return String(
    error ||
    "Unknown error"
  );

}


/* ============================================================
   CONCAT BYTES
   ============================================================ */

function concatBytes(
  a,
  b
) {

  const output =
    new Uint8Array(
      a.length +
      b.length
    );


  output.set(
    a,
    0
  );


  output.set(
    b,
    a.length
  );


  return output;

}


/* ============================================================
   HEX -> BYTES
   ============================================================ */

function hexToBytes(
  hex
) {

  const clean =
    String(hex)
      .replace(
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
      "Invalid hexadecimal signature contents."
    );

  }


  const output =
    new Uint8Array(
      clean.length / 2
    );


  for (
    let i = 0;
    i < clean.length;
    i += 2
  ) {

    const value =
      parseInt(
        clean.slice(
          i,
          i + 2
        ),
        16
      );


    if (
      Number.isNaN(value)
    ) {

      throw new Error(
        "Invalid hexadecimal byte."
      );

    }


    output[i / 2] =
      value;

  }


  return output;

}


/* ============================================================
   EXTRACT PDF /CONTENTS

   IMPORTANT:
   We search after the matching ByteRange position so that
   we do not accidentally read another signature.
   ============================================================ */

function extractSignatureContents(
  pdfText,
  byteRangePosition
) {

  const start =
    Math.max(
      0,
      Number(byteRangePosition) || 0
    );


  const section =
    pdfText.slice(
      start
    );


  /*
     Normal PDF:
       /Contents <3082....0000>
  */

  const match =
    section.match(
      /\/Contents\s*<([0-9A-Fa-f\s\r\n\t]+)>/i
    );


  if (!match) {

    return null;

  }


  return match[1];

}


/* ============================================================
   FIND CERTIFICATE FOR SIGNER
   ============================================================ */

function findCertificateForSigner(
  signerInfo,
  certificates
) {

  try {

    const sid =
      signerInfo?.sid;


    if (!sid) {

      return null;

    }


    /*
       Normal CMS SignerIdentifier:
       IssuerAndSerialNumber
    */

    if (
      sid instanceof
      pkijs.IssuerAndSerialNumber
    ) {

      for (
        const certificate of certificates
      ) {

        if (
          !(certificate instanceof pkijs.Certificate)
        ) {

          continue;

        }


        const serialMatch =
          compareArrayBuffers(
            certificate
              ?.serialNumber
              ?.valueBlock
              ?.valueHex,

            sid
              ?.serialNumber
              ?.valueBlock
              ?.valueHex
          );


        if (!serialMatch) {

          continue;

        }


        try {

          if (
            certificate
              ?.issuer
              ?.isEqual(
                sid.issuer
              )
          ) {

            return certificate;

          }

        } catch {

          /*
             Ignore issuer comparison failure and
             continue with fallback matching.
          */

        }

      }

    }


    /*
       Fallback using serial number.
    */

    const sidSerial =
      sid
        ?.serialNumber
        ?.valueBlock
        ?.valueHex;


    if (sidSerial) {

      for (
        const certificate of certificates
      ) {

        const serial =
          certificate
            ?.serialNumber
            ?.valueBlock
            ?.valueHex;


        if (
          compareArrayBuffers(
            serial,
            sidSerial
          )
        ) {

          return certificate;

        }

      }

    }


    return null;

  } catch {

    return null;

  }

}


/* ============================================================
   COMPARE ARRAY BUFFERS
   ============================================================ */

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


/* ============================================================
   CERTIFICATE SUBJECT
   ============================================================ */

function getCertificateSubject(
  cert
) {

  try {

    const values =
      cert
        ?.subject
        ?.typesAndValues ||
      [];


    const parts =
      values
        .map(
          item =>
            getASN1String(
              item
            )
        )
        .filter(Boolean);


    return parts.length
      ? parts.join(", ")
      : "Certificate subject available";

  } catch {

    return "Certificate subject unavailable";

  }

}


/* ============================================================
   CERTIFICATE ISSUER
   ============================================================ */

function getCertificateIssuer(
  cert
) {

  try {

    const values =
      cert
        ?.issuer
        ?.typesAndValues ||
      [];


    const parts =
      values
        .map(
          item =>
            getASN1String(
              item
            )
        )
        .filter(Boolean);


    return parts.length
      ? parts.join(", ")
      : "Certificate issuer available";

  } catch {

    return "Certificate issuer unavailable";

  }

}


/* ============================================================
   ASN.1 STRING
   ============================================================ */

function getASN1String(
  item
) {

  try {

    const value =
      item?.value;


    if (
      !value
    ) {

      return "";

    }


    if (
      value.valueBlock &&
      typeof value.valueBlock.value ===
        "string"
    ) {

      return value.valueBlock.value;

    }


    if (
      typeof value.value ===
        "string"
    ) {

      return value.value;

    }


    return "";

  } catch {

    return "";

  }

}


/* ============================================================
   SERIAL NUMBER
   ============================================================ */

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


/* ============================================================
   BYTES -> HEX
   ============================================================ */

function bytesToHex(
  bytes
) {

  return Array
    .from(bytes)
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(
            2,
            "0"
          )
    )
    .join("");

}


/* ============================================================
   FRONTEND
   ============================================================ */

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
  font-family:Arial,Helvetica,sans-serif;
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
  padding:50px 0 35px;
}

.header{
  text-align:center;
  margin-bottom:32px;
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
  margin:18px 0 8px;
  font-size:50px;
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
  min-height:320px;

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
  margin:15px 0 8px;
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

  font-size:20px;
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

.invalid{
  background:
    rgba(255,70,70,.12);

  border:
    1px solid
    #c94b4b;

  color:#ff7777;
}

.notdetected{
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

.error{
  margin-top:18px;

  padding:15px;

  border-radius:12px;

  color:#ff8c8c;

  background:
    rgba(255,70,70,.10);

  border:
    1px solid
    rgba(255,70,70,.25);

  display:none;

  text-align:center;
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
    rgba(0,0,0,.20);

  min-width:0;
}

.label{
  color:#91a8c2;
  font-size:13px;
  margin-bottom:7px;
}

.value{
  font-size:16px;
  font-weight:bold;
  word-break:break-word;
  line-height:1.45;
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
    padding:30px 0 25px;
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
    min-height:290px;
    padding:20px;
  }

  .drop h2{
    font-size:22px;
  }

  .grid{
    grid-template-columns:1fr;
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
<div class="label">SIGNATURE COUNT</div>
<div id="signatureCount" class="value">-</div>
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
<div class="label">CERTIFICATE COUNT</div>
<div id="certificateCount" class="value">-</div>
</div>


<div class="box">
<div class="label">CERTIFICATE CHAIN</div>
<div id="chain" class="value">-</div>
</div>


</div>


<div class="note">

⚠️ <b>Verification information:</b>

<br><br>

This tool verifies the PDF digital signature
cryptographically against the exact PDF ByteRange
using CMS / PKCS#7 and WebCrypto.

<br><br>

If the cryptographic signature is valid,
the signed PDF bytes have not been changed.

<br><br>

Certificate chain trust is shown separately.
A valid cryptographic signature does not automatically
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

let selectedFile =
  null;


/* ==========================================================
   CHOOSE FILE
   ========================================================== */

chooseBtn.addEventListener(
  "click",
  function(event){

    event.preventDefault();
    event.stopPropagation();

    input.click();

  }
);


/* ==========================================================
   DROP AREA CLICK
   ========================================================== */

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


/* ==========================================================
   FILE CHANGE
   ========================================================== */

input.addEventListener(
  "change",
  function(){

    if (
      !input.files ||
      !input.files.length
    ) {

      return;

    }

    handleFile(
      input.files[0]
    );

  }
);


/* ==========================================================
   DRAG OVER
   ========================================================== */

drop.addEventListener(
  "dragover",
  function(event){

    event.preventDefault();

    drop.classList.add(
      "dragover"
    );

  }
);


/* ==========================================================
   DRAG LEAVE
   ========================================================== */

drop.addEventListener(
  "dragleave",
  function(){

    drop.classList.remove(
      "dragover"
    );

  }
);


/* ==========================================================
   DROP
   ========================================================== */

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


/* ==========================================================
   HANDLE FILE
   ========================================================== */

function handleFile(
  file
){

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

    input.value =
      "";

    selectedFile =
      null;

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

    input.value =
      "";

    selectedFile =
      null;

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


/* ==========================================================
   VERIFY
   ========================================================== */

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
            method:
              "POST",

            body:
              formData
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


      /* ----------------------------------------------------
         BASIC FILE DATA
         ---------------------------------------------------- */

      setText(
        "fileName",
        data.file?.name || "-"
      );


      setText(
        "fileSize",
        formatBytes(
          data.file?.size || 0
        )
      );


      setText(
        "pdfValid",
        data.pdf?.validHeader
          ? "✓ Valid PDF"
          : "✗ Invalid PDF"
      );


      /* ----------------------------------------------------
         SIGNATURE STRUCTURE
         ---------------------------------------------------- */

      setText(
        "byteRange",
        data.signatureStructure?.byteRangeValid
          ? "✓ Valid"
          : "✗ Invalid"
      );


      setText(
        "contents",
        data.signatureStructure?.contents
          ? "✓ Found"
          : "✗ Not Found"
      );


      setText(
        "sigType",
        data.signatureStructure?.signatureType
          ? "✓ Found"
          : "✗ Not Found"
      );


      setText(
        "pkcs7",
        data.signatureStructure?.pkcs7SubFilter
          ? "✓ Found"
          : "✗ Not Found"
      );


      setText(
        "sigDictionary",
        data.signatureStructure?.signatureDictionary
          ? "✓ Found"
          : "✗ Not Found"
      );


      setText(
        "signatureCount",
        data.signatureStructure?.byteRangeCount ||
        0
      );


      /* ----------------------------------------------------
         VERIFICATION
         ---------------------------------------------------- */

      const verification =
        data.verification || {};


      setText(
        "cryptoStatus",
        verification.cryptographicVerification
          ? "✓ VALID"
          : "✗ NOT VERIFIED"
      );


      setText(
        "integrity",
        verification.documentIntegrity
          ? "✓ INTACT"
          : "✗ NOT VERIFIED"
      );


      setText(
        "certificate",
        verification.certificatePresent
          ? "✓ Found"
          : "✗ Not Found"
      );


      setText(
        "signer",
        verification.signer ||
        "-"
      );


      setText(
        "issuer",
        verification.issuer ||
        "-"
      );


      setText(
        "serial",
        verification.serialNumber ||
        "-"
      );


      setText(
        "certificateCount",
        verification.certificateCount ??
        0
      );


      setText(
        "chain",
        verification.certificateChainVerified
          ? "✓ Verified"
          : "Not trust-validated"
      );


      /* ----------------------------------------------------
         STATUS
         ---------------------------------------------------- */

      const status =
        document.getElementById(
          "status"
        );


      const verificationStatus =
        verification.status;


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


      /* ----------------------------------------------------
         SHOW RESULT
         ---------------------------------------------------- */

      result.scrollIntoView({
        behavior:
          "smooth",
        block:
          "start"
      });

    }

    catch(error) {

      showError(
        "❌ " +
        (
          error?.message ||
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


/* ==========================================================
   SET TEXT
   ========================================================== */

function setText(
  id,
  value
){

  const element =
    document.getElementById(
      id
    );


  if (element) {

    element.textContent =
      value;

  }

}


/* ==========================================================
   FORMAT BYTES
   ========================================================== */

function formatBytes(
  bytes
){

  if (
    !bytes ||
    bytes <= 0
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
    )
    +
    " " +
    units[i]
  );

}


/* ==========================================================
   SHOW ERROR
   ========================================================== */

function showError(
  message
){

  errorBox.style.display =
    "block";

  errorBox.textContent =
    message;

}


/* ==========================================================
   CLEAR ERROR
   ========================================================== */

function clearError(){

  errorBox.style.display =
    "none";

  errorBox.textContent =
    "";

}

</script>

</body>

</html>`;
