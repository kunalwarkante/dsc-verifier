export default {
  async fetch(request) {
    const url = new URL(request.url);

    // =========================================================
    // PDF VERIFY API
    // =========================================================
    if (url.pathname === "/api/verify" && request.method === "POST") {
      try {
        const contentType =
          request.headers.get("content-type") || "";

        if (!contentType.includes("multipart/form-data")) {
          return json(
            {
              success: false,
              error:
                "Please upload PDF using multipart/form-data."
            },
            400
          );
        }

        const formData = await request.formData();

        const file = formData.get("file");

        if (
          !file ||
          typeof file.arrayBuffer !== "function"
        ) {
          return json(
            {
              success: false,
              error: "PDF file not found."
            },
            400
          );
        }

        // -------------------------------------------------------
        // File type check
        // -------------------------------------------------------
        const fileName =
          file.name || "uploaded.pdf";

        const isPDF =
          fileName.toLowerCase().endsWith(".pdf") ||
          file.type === "application/pdf";

        if (!isPDF) {
          return json(
            {
              success: false,
              error: "Only PDF files are allowed."
            },
            400
          );
        }

        // -------------------------------------------------------
        // Maximum file size = 20 MB
        // -------------------------------------------------------
        const MAX_SIZE = 20 * 1024 * 1024;

        if (file.size > MAX_SIZE) {
          return json(
            {
              success: false,
              error:
                "PDF size must be below 20 MB."
            },
            413
          );
        }

        // -------------------------------------------------------
        // Read PDF
        // -------------------------------------------------------
        const buffer = await file.arrayBuffer();

        const bytes = new Uint8Array(buffer);

        // -------------------------------------------------------
        // Validate PDF header
        // -------------------------------------------------------
        const header =
          new TextDecoder().decode(
            bytes.slice(0, 8)
          );

        if (!header.startsWith("%PDF-")) {
          return json(
            {
              success: false,
              error:
                "Uploaded file is not a valid PDF."
            },
            400
          );
        }

        // -------------------------------------------------------
        // Convert PDF to Latin-1 text
        // -------------------------------------------------------
        const pdfText =
          new TextDecoder("latin1").decode(bytes);

        // -------------------------------------------------------
        // Digital signature structure detection
        // -------------------------------------------------------

        const hasByteRange =
          /\/ByteRange\s*\[/.test(pdfText);

        const hasContents =
          /\/Contents\s*</.test(pdfText);

        const hasSignatureType =
          /\/Type\s*\/Sig\b/.test(pdfText);

        const hasPkcs7 =
          /\/SubFilter\s*\/adbe\.pkcs7\.detached\b/.test(
            pdfText
          ) ||
          /\/SubFilter\s*\/adbe\.pkcs7\.sha1\b/.test(
            pdfText
          ) ||
          /\/SubFilter\s*\/ETSI\.CAdES\.detached\b/.test(
            pdfText
          );

        const hasSignatureDictionary =
          /\/Sig\s*<<|\/Sig\s*\//.test(pdfText);

        const signatureDetected =
          hasByteRange ||
          hasContents ||
          hasSignatureType ||
          hasPkcs7 ||
          hasSignatureDictionary;

        // -------------------------------------------------------
        // Return result
        // -------------------------------------------------------

        return json({
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
            signatureDetected:
              signatureDetected
          },

          signatureStructure: {
            byteRange: hasByteRange,
            contents: hasContents,
            signatureType:
              hasSignatureType,
            pkcs7SubFilter:
              hasPkcs7,
            signatureDictionary:
              hasSignatureDictionary
          },

          verification: {
            status: signatureDetected
              ? "STRUCTURE_DETECTED"
              : "NOT_DETECTED",

            cryptographicVerification:
              false,

            message: signatureDetected
              ? "Digital signature structure detected in the PDF."
              : "No digital signature structure detected."
          }
        });

      } catch (error) {
        return json(
          {
            success: false,
            error:
              error?.message ||
              "Unable to process PDF."
          },
          500
        );
      }
    }


    // =========================================================
    // STATUS API
    // =========================================================
    if (url.pathname === "/api/status") {
      return json({
        success: true,
        service: "DSC Verifier API",
        status: "online",
        stage:
          "PDF upload and signature structure detection"
      });
    }


    // =========================================================
    // FRONTEND
    // =========================================================
    return new Response(
      `<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1.0"
>

<title>DSC Verifier</title>

<style>

/* =========================================================
   RESET
========================================================= */

*{
  box-sizing:border-box;
}


/* =========================================================
   BODY
========================================================= */

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


/* =========================================================
   CONTAINER
========================================================= */

.container{
  width:min(1050px,94%);
  margin:auto;

  padding:
    55px 0
    35px;
}


/* =========================================================
   HEADER
========================================================= */

.header{
  text-align:center;

  margin-bottom:35px;
}


/* =========================================================
   LOGO
========================================================= */

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


/* =========================================================
   TITLE
========================================================= */

h1{
  margin:
    20px 0
    8px;

  font-size:52px;
}


/* =========================================================
   SUBTITLE
========================================================= */

.subtitle{
  color:#a9c7e8;

  font-size:18px;
}


/* =========================================================
   CARD
========================================================= */

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


/* =========================================================
   DROP AREA
========================================================= */

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

  transition:
    .2s ease;
}


/* =========================================================
   DROP HOVER
========================================================= */

.drop:hover{
  border-color:#25bfff;

  background:
    rgba(30,120,220,.08);
}


/* =========================================================
   DRAG ACTIVE
========================================================= */

.drop.dragover{
  border-color:#13c6b5;

  background:
    rgba(19,198,181,.12);

  transform:
    scale(1.01);
}


/* =========================================================
   ICON
========================================================= */

.icon{
  font-size:60px;
}


/* =========================================================
   DROP TITLE
========================================================= */

.drop h2{
  margin:
    15px 0
    8px;
}


/* =========================================================
   DROP TEXT
========================================================= */

.drop p{
  color:#aebed2;
}


/* =========================================================
   FILE INPUT
========================================================= */

input[type="file"]{
  display:none;
}


/* =========================================================
   CHOOSE BUTTON
========================================================= */

.choose-btn{

  display:inline-flex;

  align-items:center;
  justify-content:center;

  padding:
    15px 28px;

  border-radius:12px;

  color:#fff;

  font-size:16px;

  font-weight:bold;

  cursor:pointer;

  user-select:none;

  background:
    linear-gradient(
      90deg,
      #187cff,
      #13c6b5
    );

  box-shadow:
    0 8px 25px
    rgba(24,124,255,.18);

  transition:
    .2s ease;
}


/* =========================================================
   CHOOSE BUTTON HOVER
========================================================= */

.choose-btn:hover{

  transform:
    translateY(-2px);

  box-shadow:
    0 12px 30px
    rgba(24,124,255,.30);
}


/* =========================================================
   BUTTON
========================================================= */

button{

  border:0;

  padding:
    15px 28px;

  border-radius:12px;

  color:white;

  font-size:16px;

  font-weight:bold;

  cursor:pointer;

  background:
    linear-gradient(
      90deg,
      #187cff,
      #13c6b5
    );

  transition:
    .2s ease;
}


/* =========================================================
   BUTTON HOVER
========================================================= */

button:hover:not(:disabled){

  transform:
    translateY(-2px);

  box-shadow:
    0 10px 25px
    rgba(24,124,255,.25);
}


/* =========================================================
   DISABLED BUTTON
========================================================= */

button:disabled{

  opacity:.5;

  cursor:not-allowed;

  transform:none;

  box-shadow:none;
}


/* =========================================================
   FILE INFO
========================================================= */

.file{

  margin-top:20px;

  padding:15px;

  border-radius:12px;

  background:
    rgba(0,0,0,.25);

  display:none;

  word-break:break-word;

  border:
    1px solid
    rgba(255,255,255,.08);
}


/* =========================================================
   VERIFY BUTTON
========================================================= */

.verify{

  text-align:center;

  margin-top:20px;

  display:none;
}


/* =========================================================
   RESULT
========================================================= */

.result{

  display:none;

  margin-top:25px;
}


/* =========================================================
   STATUS
========================================================= */

.status{

  padding:18px;

  border-radius:15px;

  font-size:21px;

  font-weight:bold;

  text-align:center;

  margin-bottom:18px;
}


/* =========================================================
   DETECTED
========================================================= */

.detected{

  background:
    rgba(255,174,0,.15);

  border:
    1px solid
    #d99c17;

  color:
    #ffc238;
}


/* =========================================================
   NOT DETECTED
========================================================= */

.notdetected{

  background:
    rgba(255,70,70,.12);

  border:
    1px solid
    #c94b4b;

  color:
    #ff7777;
}


/* =========================================================
   ERROR
========================================================= */

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


/* =========================================================
   GRID
========================================================= */

.grid{

  display:grid;

  grid-template-columns:
    1fr 1fr;

  gap:15px;
}


/* =========================================================
   BOX
========================================================= */

.box{

  padding:18px;

  border-radius:15px;

  background:
    rgba(0,0,0,.2);
}


/* =========================================================
   LABEL
========================================================= */

.label{

  color:#91a8c2;

  font-size:13px;

  margin-bottom:6px;
}


/* =========================================================
   VALUE
========================================================= */

.value{

  font-size:17px;

  font-weight:bold;

  word-break:break-word;
}


/* =========================================================
   NOTE
========================================================= */

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


/* =========================================================
   FOOTER
========================================================= */

.footer{

  text-align:center;

  color:#6e87a4;

  margin-top:30px;

  font-size:14px;
}


/* =========================================================
   MOBILE
========================================================= */

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


  <!-- =====================================================
       HEADER
  ====================================================== -->

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


  <!-- =====================================================
       MAIN CARD
  ====================================================== -->

  <div class="card">


    <!-- ===================================================
         DROP AREA
    ==================================================== -->

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
          Select or drag & drop your digitally signed
          certificate PDF
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


    <!-- ===================================================
         HIDDEN FILE INPUT
    ==================================================== -->

    <input
      id="pdf"
      type="file"
      accept=".pdf,application/pdf"
    >


    <!-- ===================================================
         FILE INFO
    ==================================================== -->

    <div
      id="fileBox"
      class="file"
    ></div>


    <!-- ===================================================
         ERROR
    ==================================================== -->

    <div
      id="errorBox"
      class="error"
    ></div>


    <!-- ===================================================
         VERIFY BUTTON
    ==================================================== -->

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


    <!-- ===================================================
         RESULT
    ==================================================== -->

    <div
      id="result"
      class="result"
    >


      <div
        id="status"
        class="status"
      ></div>


      <div class="grid">


        <!-- FILE NAME -->

        <div class="box">

          <div class="label">
            FILE NAME
          </div>

          <div
            id="fileName"
            class="value"
          >
            -
          </div>

        </div>


        <!-- FILE SIZE -->

        <div class="box">

          <div class="label">
            FILE SIZE
          </div>

          <div
            id="fileSize"
            class="value"
          >
            -
          </div>

        </div>


        <!-- PDF -->

        <div class="box">

          <div class="label">
            PDF
          </div>

          <div
            id="pdfValid"
            class="value"
          >
            -
          </div>

        </div>


        <!-- BYTE RANGE -->

        <div class="box">

          <div class="label">
            BYTE RANGE
          </div>

          <div
            id="byteRange"
            class="value"
          >
            -
          </div>

        </div>


        <!-- CONTENTS -->

        <div class="box">

          <div class="label">
            SIGNATURE CONTENTS
          </div>

          <div
            id="contents"
            class="value"
          >
            -
          </div>

        </div>


        <!-- SIGNATURE TYPE -->

        <div class="box">

          <div class="label">
            SIGNATURE TYPE
          </div>

          <div
            id="sigType"
            class="value"
          >
            -
          </div>

        </div>


        <!-- PKCS7 -->

        <div class="box">

          <div class="label">
            PKCS#7 / CAdES
          </div>

          <div
            id="pkcs7"
            class="value"
          >
            -
          </div>

        </div>


        <!-- SIGNATURE DICTIONARY -->

        <div class="box">

          <div class="label">
            SIGNATURE DICTIONARY
          </div>

          <div
            id="sigDictionary"
            class="value"
          >
            -
          </div>

        </div>


      </div>


      <!-- =================================================
           NOTE
      ================================================== -->

      <div class="note">

        ⚠️ <b>Important:</b>

        This stage detects the digital-signature
        structure inside the PDF.

        <br><br>

        Cryptographic certificate-chain verification
        is not performed by this browser/Worker stage.

      </div>


    </div>


  </div>


  <!-- =====================================================
       FOOTER
  ====================================================== -->

  <div class="footer">

    DSC Verifier • Independent verification tool
    • Not a government website

  </div>


</div>


<script>

/* =========================================================
   ELEMENTS
========================================================= */

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


/* =========================================================
   SELECTED FILE
========================================================= */

let selectedFile = null;


/* =========================================================
   CHOOSE PDF BUTTON
========================================================= */

chooseBtn.addEventListener(
  "click",
  function(event){

    event.preventDefault();

    event.stopPropagation();

    input.click();

  }
);


/* =========================================================
   DROP AREA CLICK
========================================================= */

drop.addEventListener(
  "click",
  function(event){

    if(event.target === chooseBtn){
      return;
    }

    input.click();

  }
);


/* =========================================================
   FILE INPUT CHANGE
========================================================= */

input.addEventListener(
  "change",
  function(){

    if(!input.files.length){
      return;
    }

    handleFile(input.files[0]);

  }
);


/* =========================================================
   DRAG OVER
========================================================= */

drop.addEventListener(
  "dragover",
  function(event){

    event.preventDefault();

    drop.classList.add(
      "dragover"
    );

  }
);


/* =========================================================
   DRAG LEAVE
========================================================= */

drop.addEventListener(
  "dragleave",
  function(){

    drop.classList.remove(
      "dragover"
    );

  }
);


/* =========================================================
   DROP
========================================================= */

drop.addEventListener(
  "drop",
  function(event){

    event.preventDefault();

    drop.classList.remove(
      "dragover"
    );

    const files =
      event.dataTransfer.files;

    if(!files || !files.length){
      return;
    }

    handleFile(files[0]);

  }
);


/* =========================================================
   HANDLE FILE
========================================================= */

function handleFile(file){

  clearError();

  result.style.display =
    "none";

  verifyBox.style.display =
    "none";

  fileBox.style.display =
    "none";


  if(!file){
    return;
  }


  /* -------------------------------------------------------
     PDF check
  ------------------------------------------------------- */

  const isPDF =
    file.type === "application/pdf" ||
    file.name
      .toLowerCase()
      .endsWith(".pdf");


  if(!isPDF){

    showError(
      "❌ Please select a valid PDF file."
    );

    input.value = "";

    return;
  }


  /* -------------------------------------------------------
     20 MB check
  ------------------------------------------------------- */

  const MAX_SIZE =
    20 * 1024 * 1024;


  if(file.size > MAX_SIZE){

    showError(
      "❌ PDF size must be below 20 MB."
    );

    input.value = "";

    return;
  }


  /* -------------------------------------------------------
     Save file
  ------------------------------------------------------- */

  selectedFile = file;


  fileBox.style.display =
    "block";


  fileBox.textContent =
    "📄 Selected: " +
    file.name +
    " • " +
    formatBytes(file.size);


  verifyBox.style.display =
    "block";

}


/* =========================================================
   VERIFY BUTTON
========================================================= */

verifyBtn.addEventListener(
  "click",
  async function(){

    if(!selectedFile){

      showError(
        "Please select a PDF first."
      );

      return;
    }


    clearError();


    verifyBtn.disabled =
      true;


    verifyBtn.textContent =
      "⏳ Analyzing PDF...";


    const formData =
      new FormData();


    formData.append(
      "file",
      selectedFile
    );


    try{


      /* ---------------------------------------------------
         API request
      --------------------------------------------------- */

      const response =
        await fetch(
          "/api/verify",
          {
            method:"POST",
            body:formData
          }
        );


      let data;


      try{

        data =
          await response.json();

      }catch{

        throw new Error(
          "Invalid response from server."
        );

      }


      /* ---------------------------------------------------
         API error
      --------------------------------------------------- */

      if(!response.ok ||
         !data.success){

        throw new Error(
          data.error ||
          "Verification failed."
        );

      }


      /* ---------------------------------------------------
         Show result
      --------------------------------------------------- */

      result.style.display =
        "block";


      /* FILE NAME */

      document
        .getElementById("fileName")
        .textContent =
          data.file.name;


      /* FILE SIZE */

      document
        .getElementById("fileSize")
        .textContent =
          formatBytes(
            data.file.size
          );


      /* PDF */

      document
        .getElementById("pdfValid")
        .textContent =
          data.pdf.validHeader
            ? "Valid PDF"
            : "Invalid PDF";


      /* BYTE RANGE */

      document
        .getElementById("byteRange")
        .textContent =
          data.signatureStructure.byteRange
            ? "✓ Found"
            : "✗ Not Found";


      /* CONTENTS */

      document
        .getElementById("contents")
        .textContent =
          data.signatureStructure.contents
            ? "✓ Found"
            : "✗ Not Found";


      /* SIGNATURE TYPE */

      document
        .getElementById("sigType")
        .textContent =
          data.signatureStructure.signatureType
            ? "✓ Found"
            : "✗ Not Found";


      /* PKCS7 */

      document
        .getElementById("pkcs7")
        .textContent =
          data.signatureStructure.pkcs7SubFilter
            ? "✓ Found"
            : "✗ Not Found";


      /* SIGNATURE DICTIONARY */

      document
        .getElementById("sigDictionary")
        .textContent =
          data.signatureStructure.signatureDictionary
            ? "✓ Found"
            : "✗ Not Found";


      /* ---------------------------------------------------
         STATUS
      --------------------------------------------------- */

      const status =
        document.getElementById(
          "status"
        );


      if(
        data.pdf.signatureDetected
      ){

        status.className =
          "status detected";


        status.textContent =
          "⚠️ DIGITAL SIGNATURE STRUCTURE DETECTED";

      }else{

        status.className =
          "status notdetected";


        status.textContent =
          "❌ DIGITAL SIGNATURE NOT DETECTED";

      }


      /* ---------------------------------------------------
         Scroll to result
      --------------------------------------------------- */

      result.scrollIntoView({
        behavior:"smooth",
        block:"start"
      });


    }catch(error){

      showError(
        "❌ " +
        (
          error.message ||
          "Unable to connect to verification server."
        )
      );

    }finally{

      verifyBtn.disabled =
        false;


      verifyBtn.textContent =
        "🔍 Verify PDF";

    }

  }
);


/* =========================================================
   FORMAT BYTES
========================================================= */

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
    Math.floor(
      Math.log(bytes) /
      Math.log(1024)
    );


  return (
    parseFloat(
      (
        bytes /
        Math.pow(1024,i)
      ).toFixed(2)
    )
    +
    " "
    +
    units[i]
  );

}


/* =========================================================
   SHOW ERROR
========================================================= */

function showError(message){

  errorBox.style.display =
    "block";

  errorBox.textContent =
    message;

}


/* =========================================================
   CLEAR ERROR
========================================================= */

function clearError(){

  errorBox.style.display =
    "none";

  errorBox.textContent =
    "";

}

</script>


</body>

</html>`,
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


// =========================================================
// JSON HELPER
// =========================================================

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
