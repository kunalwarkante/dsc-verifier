export default {
  async fetch(request) {
    const url = new URL(request.url);

    // =========================
    // PDF VERIFY API
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
            error: "PDF file not found."
          }, 400);
        }

        const MAX_SIZE = 20 * 1024 * 1024;

        if (file.size > MAX_SIZE) {
          return json({
            success: false,
            error: "PDF size must be below 20 MB."
          }, 413);
        }

        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);

        const header = new TextDecoder().decode(bytes.slice(0, 8));

        if (!header.startsWith("%PDF-")) {
          return json({
            success: false,
            error: "Uploaded file is not a valid PDF."
          }, 400);
        }

        const pdfText = new TextDecoder("latin1").decode(bytes);

        const hasByteRange = /\/ByteRange\s*\[/.test(pdfText);
        const hasContents = /\/Contents\s*</.test(pdfText);
        const hasSignatureType = /\/Type\s*\/Sig\b/.test(pdfText);

        const hasPkcs7 =
          /\/SubFilter\s*\/adbe\.pkcs7\.detached\b/.test(pdfText) ||
          /\/SubFilter\s*\/adbe\.pkcs7\.sha1\b/.test(pdfText);

        const signatureDetected =
          hasByteRange ||
          hasContents ||
          hasSignatureType ||
          hasPkcs7;

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
            pkcs7SubFilter: hasPkcs7
          },

          verification: {
            status: "PENDING",
            cryptographicVerification: false,
            message: signatureDetected
              ? "Digital signature structure detected."
              : "No digital signature structure detected."
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
    // STATUS API
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
    // FRONTEND
    // =========================
    return new Response(`<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">

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
    radial-gradient(circle at 10% 10%,#183a91 0%,transparent 35%),
    radial-gradient(circle at 90% 90%,#006d66 0%,transparent 35%),
    #06101f;
}

.container{
  width:min(1050px,94%);
  margin:auto;
  padding:55px 0 35px;
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
  background:linear-gradient(135deg,#247cff,#13c6b5);
  box-shadow:0 15px 40px rgba(0,0,0,.35);
}

h1{
  margin:20px 0 8px;
  font-size:52px;
}

.subtitle{
  color:#a9c7e8;
  font-size:18px;
}

.card{
  padding:25px;
  border-radius:26px;
  background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.16);
  backdrop-filter:blur(12px);
  box-shadow:0 25px 70px rgba(0,0,0,.3);
}

.drop{
  min-height:330px;
  border:2px dashed rgba(180,210,245,.45);
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
  background:rgba(30,120,220,.08);
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

input{
  display:none;
}

button{
  border:0;
  padding:15px 28px;
  border-radius:12px;
  color:white;
  font-size:16px;
  font-weight:bold;
  cursor:pointer;
  background:linear-gradient(90deg,#187cff,#13c6b5);
}

button:disabled{
  opacity:.5;
  cursor:not-allowed;
}

.file{
  margin-top:20px;
  padding:15px;
  border-radius:12px;
  background:rgba(0,0,0,.25);
  display:none;
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

.detected{
  background:rgba(255,174,0,.15);
  border:1px solid #d99c17;
  color:#ffc238;
}

.notdetected{
  background:rgba(255,70,70,.12);
  border:1px solid #c94b4b;
  color:#ff7777;
}

.grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:15px;
}

.box{
  padding:18px;
  border-radius:15px;
  background:rgba(0,0,0,.2);
}

.label{
  color:#91a8c2;
  font-size:13px;
  margin-bottom:6px;
}

.value{
  font-size:17px;
  font-weight:bold;
}

.note{
  margin-top:18px;
  padding:16px;
  border-radius:14px;
  color:#a9c8e8;
  background:rgba(30,120,220,.10);
  border:1px solid rgba(80,160,240,.2);
}

.footer{
  text-align:center;
  color:#6e87a4;
  margin-top:30px;
  font-size:14px;
}

@media(max-width:650px){
  h1{
    font-size:38px;
  }

  .grid{
    grid-template-columns:1fr;
  }
}

</style>
</head>

<body>

<div class="container">

  <div class="header">

    <div class="logo">🔐</div>

    <h1>DSC Verifier</h1>

    <div class="subtitle">
      Digital Signature Certificate Verification Tool
    </div>

  </div>


  <div class="card">

    <label class="drop" for="pdf">

      <div>

        <div class="icon">📄</div>

        <h2>Upload Digitally Signed PDF</h2>

        <p>
          Select or drag & drop your digitally signed certificate PDF
        </p>

        <br>

        <button type="button">
          Choose PDF
        </button>

      </div>

    </label>

    <input id="pdf" type="file" accept=".pdf,application/pdf">


    <div id="fileBox" class="file"></div>


    <div id="verifyBox" class="verify">

      <button id="verifyBtn">
        🔍 Verify PDF
      </button>

    </div>


    <div id="result" class="result">

      <div id="status" class="status"></div>

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
          <div class="label">SIGNATURE TYPE</div>
          <div id="sigType" class="value">-</div>
        </div>

        <div class="box">
          <div class="label">PKCS#7</div>
          <div id="pkcs7" class="value">-</div>
        </div>

      </div>


      <div class="note">
        ⚠️ <b>Important:</b>
        This stage detects the digital-signature structure inside the PDF.
        Cryptographic certificate-chain verification will be implemented
        in the next stage.
      </div>

    </div>

  </div>


  <div class="footer">
    DSC Verifier • Independent verification tool • Not a government website
  </div>

</div>


<script>

const input = document.getElementById("pdf");
const fileBox = document.getElementById("fileBox");
const verifyBox = document.getElementById("verifyBox");
const verifyBtn = document.getElementById("verifyBtn");
const result = document.getElementById("result");

let selectedFile = null;


input.addEventListener("change", () => {

  selectedFile = input.files[0];

  if(!selectedFile){
    return;
  }

  fileBox.style.display = "block";

  fileBox.textContent =
    "Selected: " + selectedFile.name;

  verifyBox.style.display = "block";

  result.style.display = "none";

});


verifyBtn.addEventListener("click", async () => {

  if(!selectedFile){
    return;
  }

  verifyBtn.disabled = true;
  verifyBtn.textContent = "⏳ Analyzing PDF...";

  const formData = new FormData();

  formData.append("file", selectedFile);


  try{

    const response = await fetch("/api/verify", {
      method:"POST",
      body:formData
    });


    const data = await response.json();


    if(!data.success){

      alert(data.error || "Verification failed.");

      return;
    }


    result.style.display = "block";


    document.getElementById("fileName").textContent =
      data.file.name;

    document.getElementById("fileSize").textContent =
      formatBytes(data.file.size);

    document.getElementById("pdfValid").textContent =
      data.pdf.validHeader ? "Valid PDF" : "Invalid PDF";

    document.getElementById("byteRange").textContent =
      data.signatureStructure.byteRange ? "Found" : "Not Found";

    document.getElementById("sigType").textContent =
      data.signatureStructure.signatureType ? "Found" : "Not Found";

    document.getElementById("pkcs7").textContent =
      data.signatureStructure.pkcs7SubFilter ? "Found" : "Not Found";


    const status = document.getElementById("status");


    if(data.pdf.signatureDetected){

      status.className = "status detected";

      status.textContent =
        "⚠️ DIGITAL SIGNATURE STRUCTURE DETECTED";

    }else{

      status.className = "status notdetected";

      status.textContent =
        "❌ DIGITAL SIGNATURE NOT DETECTED";

    }


  }catch(error){

    alert("Unable to connect to verification server.");

  }finally{

    verifyBtn.disabled = false;
    verifyBtn.textContent = "🔍 Verify PDF";

  }

});


function formatBytes(bytes){

  if(bytes === 0){
    return "0 Bytes";
  }

  const units = [
    "Bytes",
    "KB",
    "MB",
    "GB"
  ];

  const i =
    Math.floor(Math.log(bytes) / Math.log(1024));

  return (
    parseFloat(
      (bytes / Math.pow(1024,i)).toFixed(2)
    )
    + " "
    + units[i]
  );

}

</script>

</body>
</html>`, {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store"
      }
    });
  }
};


// JSON helper
function json(data, status = 200) {
  return new Response(
    JSON.stringify(data, null, 2),
    {
      status,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store"
      }
    }
  );
}
