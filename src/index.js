export default {
  async fetch() {
    return new Response("DSC Verifier API - Setup OK", {
      headers: {
        "content-type": "text/plain; charset=UTF-8"
      }
    });
  }
};
